package packetstream

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	log "github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/jipanyang/hpinggo/options"
)

func logUDPReply(packet gopacket.Packet, key string) {
	fmt.Fprintf(os.Stdout, "[%v] got UDP reply\n", key)
	log.V(2).Infof("%v", packet)
}

// udpStream
type udpStream struct {
	key                              key                   // This is supposed to be client 2 server key, egress in our case.
	bytesEgress, bytesIngress, bytes int64                 // Total bytes seen on this stream.
	ciEgress, ciIngress              *gopacket.CaptureInfo // To store the CaptureInfo seen on first packet of each direction
	lastPacketSeen                   time.Time             // last time we saw a packet from either stream.
	done                             bool                  // if true, we've seen the last packet we're going to for this stream.
}

// maybeFinish print out stats.
// TODO: do something more meaningful.
func (s *udpStream) maybeFinish() {
	switch {
	case s.ciEgress == nil:
		log.Fatalf("Egress missing: [%v]", s)
	case s.ciIngress == nil:
		log.V(5).Infof("Ingress missing: [%v]", s)
	case !s.done:
		log.V(5).Infof("still waiting on stream: [%v] ", s)
	default:
		log.V(5).Infof("[%v] FINISHED, bytes: %d tx, %d rx", s.key, s.bytesEgress, s.bytesIngress)
	}
}

// udpStreamFactory implements reassembly.StreamFactory
// It also implement StreamProtocolLayer interface
type udpStreamFactory struct {
	ctx     context.Context
	streams map[key]*udpStream

	localEnpoint gopacket.Endpoint
	// the RWMutex is for protecting recvCount (for now) which may be updated in waitPackets
	// and read in sendPackets
	mu sync.RWMutex
	// Number of packets sent
	sentPackets int64
	// Number of packets received.
	recvCount              int64
	rttMin, rttMax, rttAvg int64

	// options specified at user command line
	cmdOpts options.Options
	// convenient variables derived from options
	baseDestPort     uint16
	incDestPort      bool
	forceIncDestPort bool

	// The dynamic port number which may be derived in real time
	dstPort uint16
	srcPort uint16
	srcTTL  uint8 // TTL
}

// Create a new stream factory for UDP transport layer
func newUdpStreamFactory(ctx context.Context, opt options.Options) *udpStreamFactory {
	f := &udpStreamFactory{
		ctx:       ctx,
		streams:   make(map[key]*udpStream),
		recvCount: 0,
		cmdOpts:   opt,
	}

	// Make the option setting available more conveniently
	f.parseOptions()
	// Set the starting point for dest and srouce ports
	f.dstPort = f.baseDestPort
	f.srcPort = uint16(opt.BaseSourcePort)

	if opt.TTL > 0 {
		f.srcTTL = uint8(opt.TTL)
	} else if opt.TraceRoute {
		f.srcTTL = 1
	} else {
		f.srcTTL = 64
		if opt.IPv6 {
			f.srcTTL = 255
		}
	}

	return f
}

func (f *udpStreamFactory) delete(s *udpStream) {
	delete(f.streams, s.key) // remove it from our map.
}

func (f *udpStreamFactory) parseOptions() {
	destPortStr := f.cmdOpts.DestPort

	if destPortStr[:1] == "+" {
		f.incDestPort = true
		destPortStr = destPortStr[1:]
	}
	if destPortStr[:1] == "+" {
		f.forceIncDestPort = true
		destPortStr = destPortStr[1:]
	}

	port, err := strconv.Atoi(destPortStr)
	if err != nil {
		log.Exitf("Invalid dest port: %v, %v\n", f.cmdOpts.DestPort, err)
	}
	f.baseDestPort = uint16(port)
}

func (f *udpStreamFactory) PrepareProtocalLayers(netLayer gopacket.NetworkLayer) []gopacket.Layer {
	// Prepare for next call, this makes udpStreamFactory stateful
	if f.forceIncDestPort {
		f.dstPort = f.baseDestPort + uint16(f.sentPackets)
	} else if f.incDestPort {
		// recvCount may be updated in another routine, protect it with read lock
		f.mu.RLock()
		f.dstPort = f.baseDestPort + uint16(f.recvCount)
		f.mu.RUnlock()
	}

	// Update source port number unless asked to stay const
	if !f.cmdOpts.KeepConstSourcePort {
		f.srcPort = uint16(f.cmdOpts.BaseSourcePort) + uint16(f.sentPackets)
	}

	// TODO: populating the whole udp layer every time, improve it?
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(f.srcPort),
		DstPort: layers.UDPPort(f.dstPort),
	}
	udp.SetNetworkLayerForChecksum(netLayer)

	switch v := netLayer.(type) {
	case *layers.IPv4:
		v.Protocol = layers.IPProtocolUDP
		v.TTL = f.srcTTL
	case *layers.IPv6:
		v.NextHeader = layers.IPProtocolUDP
		v.HopLimit = f.srcTTL
	default:
		panic("Unsupported network layer value")
	}

	return []gopacket.Layer{udp}
}

func (f *udpStreamFactory) OnSend(netLayer gopacket.NetworkLayer, transportLayers []gopacket.Layer, payload []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sentPackets += 1
	if !f.cmdOpts.TraceRouteKeepTTL {
		f.srcTTL++
	}

	netFlow := netLayer.NetworkFlow()
	// TODO: check length of slice
	transportLayer := transportLayers[0]
	// Need the workaroud "udp.SetInternalPortsForTesting()" to get correct transport flow key
	udp := transportLayer.(*layers.UDP)
	udp.SetInternalPortsForTesting()
	udpFlow := udp.TransportFlow()

	k := key{netFlow, udpFlow}
	if f.streams[k] != nil {
		log.Infof("[%v] found existing stream", k)
		f.streams[k].lastPacketSeen = time.Now()
		return
	}

	// Fake CaptureInfo since we don't capture on egress
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: (len(payload)) + 8, // is 8 the header length?
		Length:        (len(payload)) + 8,
	}
	s := &udpStream{key: k, ciEgress: &ci, lastPacketSeen: ci.Timestamp}
	f.streams[k] = s

	log.V(5).Infof("[%v] created UDP session", k)

}

// TODO: check sequence number of each packet sent or received.
func (f *udpStreamFactory) OnReceive(packet gopacket.Packet) {
	log.V(7).Infof("%v", packet)
	f.mu.Lock()
	defer f.mu.Unlock()

	// TODO: handle icmp reply for the packet.
	if packet.NetworkLayer() == nil {
		log.Errorf("Unusable packet: %v", packet)
		return
	}
	netflow := packet.NetworkLayer().NetworkFlow()
	// Deal with packets targeting local endpoint for stream processing. May need change for other features.
	if f.localEnpoint != netflow.Dst() {
		log.V(5).Infof("Skip non-ingress packets: %v", packet)
		return
	}
	var s *udpStream = nil
	// record the icmp reply for udp stream
	if !f.cmdOpts.IPv6 {
		icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if ok {
			typeCode := icmp.TypeCode
			if typeCode.Type() == layers.ICMPv4TypeDestinationUnreachable ||
				typeCode.Type() == layers.ICMPv4TypeTimeExceeded {
				payload, ok := packet.Layer(gopacket.LayerTypePayload).(*gopacket.Payload)
				if ok {
					FlowKey, err := parseIcmpErrorMessage(payload.LayerContents(), layers.LayerTypeIPv4)
					if err != nil {
						log.Infof("Parse ICMP message error: %v\n", err)
					} else {
						egressFlowKey := FlowKey.(key)
						log.V(2).Infof("ICMP payload egress key : %+v", egressFlowKey)
						s = f.streams[egressFlowKey]
						if s != nil {
							if f.cmdOpts.TraceRoute {
								ttl := f.srcTTL
								if !f.cmdOpts.TraceRouteKeepTTL {
									ttl -= 1
								}
								logTraceRouteIPv4(ttl, s.ciEgress, typeCode, packet)
								// fmt.Fprintf(os.Stdout, "hop=%v original flow %v\n", f.srcTTL, egressFlowKey)
							} else {
								logICMPv4(typeCode, egressFlowKey.String(), s.ciEgress, packet)
							}

						} else {
							log.V(1).Infof("no matching for %v. Timed out?", egressFlowKey)
						}
					}

				} else {
					log.V(1).Infof("No payload in icmp : %+v", icmp)
				}
			} else {
				log.V(1).Infof("Unusable icmp typeCode: %+v", icmp.TypeCode)
			}
			// This is an ICMP message but no matching udp content found there.
			if s == nil {
				log.V(5).Infof("Unusable packet: %v", packet)
				return
			}
		}
	} else {
		icmp, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
		if ok {
			typeCode := icmp.TypeCode
			if typeCode.Type() == layers.ICMPv6TypeDestinationUnreachable ||
				typeCode.Type() == layers.ICMPv6TypeTimeExceeded {
				payload, ok := packet.Layer(gopacket.LayerTypePayload).(*gopacket.Payload)
				if ok {
					// The first 4 bytes is Unused for the two types of icmpv6 message
					// https://tools.ietf.org/html/rfc4443#section-3.1
					p := gopacket.NewPacket(payload.LayerContents()[4:], layers.LayerTypeIPv6, gopacket.Default)
					if p.TransportLayer() != nil && p.TransportLayer().LayerType() == layers.LayerTypeUDP {
						kEgress := key{p.NetworkLayer().NetworkFlow(), p.TransportLayer().TransportFlow()}
						s = f.streams[kEgress]
						if s != nil {
							if f.cmdOpts.TraceRoute {
								ttl := f.srcTTL
								if !f.cmdOpts.TraceRouteKeepTTL {
									ttl -= 1
								}
								logTraceRouteIPv6(ttl, s.ciEgress, typeCode, packet)
							} else {
								logICMPv6(typeCode, kEgress.String(), s.ciEgress, packet)
							}

						} else {
							log.Infof(" %v timed out?", kEgress)
						}
					}
				}
			}
			// This is an ICMPv6 message  but no matching udp content found there.
			if s == nil {
				log.Infof("Unusable packet: %v", packet)
				return
			}
		}
	}
	if s == nil {
		if packet.TransportLayer() == nil ||
			packet.TransportLayer().LayerType() != layers.LayerTypeUDP {
			log.Errorf("Unusable packet: %v", packet)
			return
		}

		kIngress := key{packet.NetworkLayer().NetworkFlow(), packet.TransportLayer().TransportFlow()}
		if f.streams[kIngress] != nil {
			// There was bidirection flows for this key.
			// TODO: warning depending on test caases.
			log.Infof("[%v] found existing stream", kIngress)
		}
		kEgress := key{kIngress.net.Reverse(), kIngress.transport.Reverse()}
		s = f.streams[kEgress]
		if s != nil {
			logUDPReply(packet, kEgress.String())
		} else {
			log.V(5).Infof("[%s] not found", kEgress)
		}

	}

	// Found ingress flow for the corresponding egress flow.
	if s != nil {
		log.V(5).Infof("[%v]: The opposite ingress packet arrived", s.key)
		meta := packet.Metadata()
		s.bytesIngress += int64(meta.CaptureLength)
		s.ciIngress = &meta.CaptureInfo

		if s.lastPacketSeen.Before(s.ciIngress.Timestamp) {
			s.lastPacketSeen = s.ciIngress.Timestamp
		}
		f.updateStreamRecvStats(s.ciIngress, s.ciEgress)
		s.done = true
		s.maybeFinish()
		f.delete(s)
	}
}

func (f *udpStreamFactory) SetLocalEnpoint(endpoint gopacket.Endpoint) {
	f.localEnpoint = endpoint
}

// CollectOldStreams finds any streams that haven't received a packet within
// 'timeout'
func (f *udpStreamFactory) CollectOldStreams(timeout time.Duration) {
	cutoff := time.Now().Add(-timeout)
	f.mu.Lock()
	defer f.mu.Unlock()

	for k, s := range f.streams {
		if s.lastPacketSeen.Before(cutoff) {
			log.V(5).Infof("[%v] timing out old session", s.key)
			delete(f.streams, k) // remove it from our map.
			s.maybeFinish()      // Do something...?
		}
	}
}

func (f *udpStreamFactory) updateStreamRecvStats(ciIngress *gopacket.CaptureInfo, ciEgress *gopacket.CaptureInfo) {
	f.recvCount += 1

	delay := int64(ciIngress.Timestamp.Sub(ciEgress.Timestamp) / time.Nanosecond)

	if f.rttMin > delay {
		f.rttMin = delay
	}
	if f.rttMax < delay {
		f.rttMax = delay
	}
	f.rttAvg = (f.rttAvg*(f.recvCount-1) + delay) / f.recvCount
}

func (f *udpStreamFactory) ShowStats() {
	fmt.Fprintf(os.Stdout, "\n--- hpinggo statistic ---\n")
	fmt.Fprintf(os.Stdout, "%v packets tramitted, %v packets received\n",
		f.sentPackets, f.recvCount)
	fmt.Fprintf(os.Stdout, "round-trip min/avg/max = %v/%v/%v\n",
		time.Duration(f.rttMin)*time.Nanosecond,
		time.Duration(f.rttAvg)*time.Nanosecond,
		time.Duration(f.rttMax)*time.Nanosecond)
}
