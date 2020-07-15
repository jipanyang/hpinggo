package packetstream

import (
	"context"
	"fmt"
	log "github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/jipanyang/hpinggo/options"
	"os"
	"strconv"
	"sync"
	"time"
)

func LogUDPReply(packet gopacket.Packet, key string) {
	fmt.Fprintf(os.Stderr, "[%v] got UDP reply\n", key)
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
// It also implement streamProtocolLayer interface
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

func (f *udpStreamFactory) prepareProtocalLayer(netLayer gopacket.NetworkLayer) gopacket.Layer {
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
	case *layers.IPv6:
		v.NextHeader = layers.IPProtocolUDP
	default:
		panic("Unsupported network layer value")
	}

	return udp
}

func (f *udpStreamFactory) onSend(netLayer gopacket.NetworkLayer, transportLayer gopacket.Layer, payload []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sentPackets += 1

	netFlow := netLayer.NetworkFlow()

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
func (f *udpStreamFactory) onReceive(packet gopacket.Packet) {
	log.V(7).Infof("%v", packet)
	f.mu.Lock()
	defer f.mu.Unlock()

	// TODO: handle icmp reply for the packet.
	if packet.NetworkLayer() == nil {
		log.Errorf("Unusable packet: %v", packet)
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
					p := gopacket.NewPacket(payload.LayerContents(), layers.LayerTypeIPv4, gopacket.Default)
					if p.TransportLayer() != nil && p.TransportLayer().LayerType() == layers.LayerTypeUDP {
						kEgress := key{p.NetworkLayer().NetworkFlow(), p.TransportLayer().TransportFlow()}
						s = f.streams[kEgress]
						if s != nil {
							LogICMPv4(typeCode, kEgress.String(), packet)
						} else {
							log.Infof(" %v timed out?", kEgress)
						}
					}
				}
			}
			// This is an ICMP reply but no matching udp content found there.
			if s == nil {
				log.Errorf("Unusable packet: %v", packet)
				return
			}
		}
	} else {
		// TODO: handle icmpv6
		icmp, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
		if ok {
			_ = icmp
			return
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
			LogUDPReply(packet, kEgress.String())
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

func (f *udpStreamFactory) setLocalEnpoint(endpoint gopacket.Endpoint) {
	f.localEnpoint = endpoint
}

// collectOldStreams finds any streams that haven't received a packet within
// 'timeout'
func (f *udpStreamFactory) collectOldStreams(timeout time.Duration) {
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

func (f *udpStreamFactory) showStats() {
	fmt.Fprintf(os.Stderr, "\n--- hpinggo statistic ---\n")
	fmt.Fprintf(os.Stderr, "%v packets tramitted, %v packets received\n",
		f.sentPackets, f.recvCount)
	fmt.Fprintf(os.Stderr, "round-trip min/avg/max = %v/%v/%v\n",
		time.Duration(f.rttMin)*time.Nanosecond,
		time.Duration(f.rttAvg)*time.Nanosecond,
		time.Duration(f.rttMax)*time.Nanosecond)
}
