package packetstream

import (
	"context"
	"fmt"
	log "github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/jipanyang/hpinggo/options"
	"net"
	"os"
	"sync"
	"time"
)

// for tracking icmp request and reply
// IPv6:
//   ICMPv6TypeEchoRequest/Reply
// Not supporting stream matching for other ICMP messages like
//   ICMPv6NeighborSolicitation /ICMPv6NeighborAdvertisement

func LogICMPv6(typeCode layers.ICMPv6TypeCode, key string, ciEgress *gopacket.CaptureInfo, packet gopacket.Packet) {
	delay := packet.Metadata().CaptureInfo.Timestamp.Sub(ciEgress.Timestamp)

	fmt.Fprintf(os.Stderr, "[%v] %v  rtt=%v\n", key, typeCode.String(), delay)
	log.V(2).Infof("%v", packet)
}

func LogTraceRouteIPv6(ttl uint8, ciEgress *gopacket.CaptureInfo, typeCode layers.ICMPv6TypeCode, packet gopacket.Packet) {
	netflow := packet.NetworkLayer().NetworkFlow()
	ipv6 := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	name, _ := net.LookupAddr(ipv6.SrcIP.String())
	delay := packet.Metadata().CaptureInfo.Timestamp.Sub(ciEgress.Timestamp)

	fmt.Fprintf(os.Stderr, "hop=%v %v rtt=%v %v%v->%v\n",
		ttl, typeCode.String(), delay, netflow.Src(), name, netflow.Dst())

	// fmt.Fprintf(os.Stderr, "hop=%v hoprtt=%v from %v\n", ttl, delay, name)
	log.V(2).Infof("%v", packet)
}

// TODO: Add other fields neccesary to track the messages
type icmpv6Key struct {
	net gopacket.Flow
	id  uint16
	seq uint16
}

// String prints out the key in a human-readable fashion.
func (k icmpv6Key) String() string {
	return fmt.Sprintf("%v  %+v:%+v", k.net, k.id, k.seq)
}

// icmpv6Stream
type icmpv6Stream struct {
	key                              icmpv6Key             // This is supposed to be client 2 server key, egress in our case.
	bytesEgress, bytesIngress, bytes int64                 // Total bytes seen on this stream.
	ciEgress, ciIngress              *gopacket.CaptureInfo // To store the CaptureInfo seen on first packet of each direction
	lastPacketSeen                   time.Time             // last time we saw a packet from either stream.
	done                             bool                  // if true, we've seen the last packet we're going to for this stream.
}

// maybeFinish print out stats.
// TODO: do something more meaningful.
func (s *icmpv6Stream) maybeFinish() {
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

// icmpv6StreamFactory implements reassembly.StreamFactory
// It also implement streamProtocolLayer interface
type icmpv6StreamFactory struct {
	ctx     context.Context
	streams map[icmpv6Key]*icmpv6Stream

	localEnpoint gopacket.Endpoint
	// TODO: evaluate usage of this mutex
	mu sync.RWMutex
	// Number of packets sent
	sentPackets int64
	// Number of packets received.
	recvCount              int64
	rttMin, rttMax, rttAvg int64

	// options specified at user command line
	cmdOpts options.Options

	id  uint16
	seq uint16

	srcTTL uint8 // TTL
}

// Create a new stream factory for ICMP transport layer
func newIcmpv6StreamFactory(ctx context.Context, opt options.Options) *icmpv6StreamFactory {
	f := &icmpv6StreamFactory{
		ctx:       ctx,
		streams:   make(map[icmpv6Key]*icmpv6Stream),
		recvCount: 0,
		cmdOpts:   opt,
	}

	// Make the option setting available more conveniently
	f.parseOptions()
	// Set the starting point for dest and srouce ports
	f.id = uint16(os.Getppid())
	f.seq = 0

	if opt.TTL > 0 {
		f.srcTTL = uint8(opt.TTL)
	} else if opt.TraceRoute {
		f.srcTTL = 1
	} else {
		f.srcTTL = 255
	}

	return f
}

func (f *icmpv6StreamFactory) delete(s *icmpv6Stream) {
	delete(f.streams, s.key) // remove it from our map.
}

func (f *icmpv6StreamFactory) parseOptions() {

}

// Prepare ICMPv6 layers
func (f *icmpv6StreamFactory) prepareProtocalLayers(netLayer gopacket.NetworkLayer) []gopacket.Layer {
	f.seq++

	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(uint8(f.cmdOpts.Icmpv6Type), uint8(f.cmdOpts.Icmpv6Code)),
	}
	icmpv6.SetNetworkLayerForChecksum(netLayer)

	// Update network layer according local info
	switch v := netLayer.(type) {
	case *layers.IPv6:
		v.NextHeader = layers.IPProtocolICMPv6
		v.HopLimit = f.srcTTL
	default:
		panic("Unsupported network layer value")
	}

	switch f.cmdOpts.Icmpv6Type {
	case layers.ICMPv6TypeEchoRequest:
		icmpv6Echo := &layers.ICMPv6Echo{
			Identifier: f.id,
			SeqNumber:  f.seq,
		}
		return []gopacket.Layer{icmpv6, icmpv6Echo}

	default:
		panic("Unsupported icmpv6type")
	}
}

func (f *icmpv6StreamFactory) onSend(netLayer gopacket.NetworkLayer, icmpLayers []gopacket.Layer, payload []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sentPackets += 1
	if !f.cmdOpts.TraceRouteKeepTTL {
		f.srcTTL++
	}

	netFlow := netLayer.NetworkFlow()

	var k icmpv6Key

	// TODO: check length of icmpLayers
	icmpLayer := icmpLayers[0]
	icmpv6 := icmpLayer.(*layers.ICMPv6)
	if icmpv6.TypeCode.Type() == layers.ICMPv6TypeEchoRequest {
		icmpLayer = icmpLayers[1]
		icmpv6Echo := icmpLayer.(*layers.ICMPv6Echo)
		k = icmpv6Key{netFlow, icmpv6Echo.Identifier, icmpv6Echo.SeqNumber}
	}

	if f.streams[k] != nil {
		log.Infof("[%v] found existing stream", k)
		f.streams[k].lastPacketSeen = time.Now()
		return
	}

	// Fake CaptureInfo since we don't capture on egress
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: (len(payload)) + 8, // TODO: fix the length
		Length:        (len(payload)) + 8, // TODO: fix the length
	}
	s := &icmpv6Stream{key: k, ciEgress: &ci, lastPacketSeen: ci.Timestamp}
	f.streams[k] = s

	log.V(5).Infof("[%v] created ICMP session", k)
}

// TODO: check sequence number of each packet sent or received.
func (f *icmpv6StreamFactory) onReceive(packet gopacket.Packet) {
	log.V(7).Infof("%v", packet)
	f.mu.Lock()
	defer f.mu.Unlock()

	if packet.NetworkLayer() == nil {
		log.Errorf("Unusable packet: %v", packet)
		return
	}
	icmp, ok := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if !ok {
		log.Errorf("Unusable packet: %v", packet)
		return
	}

	typeCode := icmp.TypeCode

	var s *icmpv6Stream
	var kEgress icmpv6Key

	netflow := packet.NetworkLayer().NetworkFlow()
	if typeCode.Type() == layers.ICMPv6TypeEchoReply {
		icmpv6Echo, ok := packet.Layer(layers.LayerTypeICMPv6Echo).(*layers.ICMPv6Echo)
		if ok {
			kEgress = icmpv6Key{netflow.Reverse(), icmpv6Echo.Identifier, icmpv6Echo.SeqNumber}
			// Found ingress flow for the corresponding egress flow.
			s = f.streams[kEgress]
		}
	}
	if s == nil && f.cmdOpts.TraceRoute {
		if typeCode.Type() == layers.ICMPv6TypeDestinationUnreachable ||
			typeCode.Type() == layers.ICMPv6TypeTimeExceeded {
			payload, ok := packet.Layer(gopacket.LayerTypePayload).(*gopacket.Payload)
			if ok {
				// Parsing through content of icmp reply. Assuming all ok, otherwise crash
				// The first 4 bytes is Unused for the two types of icmpv6 message
				// https://tools.ietf.org/html/rfc4443#section-3.1
				p := gopacket.NewPacket(payload.LayerContents()[4:], layers.LayerTypeIPv6, gopacket.Default)
				icmpv6Echo, ok := p.Layer(layers.LayerTypeICMPv6Echo).(*layers.ICMPv6Echo)
				if ok {
					netflow = p.NetworkLayer().NetworkFlow()
					kEgress = icmpv6Key{netflow, icmpv6Echo.Identifier, icmpv6Echo.SeqNumber}
					s = f.streams[kEgress]
					if s != nil {
						if f.cmdOpts.TraceRoute {
							LogTraceRouteIPv6(f.srcTTL, s.ciEgress, typeCode, packet)
							// fmt.Fprintf(os.Stderr, "hop=%v original flow %v\n", f.srcTTL, kEgress)
						}
					}
				}
			}
		}
	}

	if s == nil {
		log.V(2).Infof("Unusable packet: %v", packet)
	} else {
		log.V(5).Infof("[%v]: The opposite ingress packet arrived", s.key)
		meta := packet.Metadata()
		s.bytesIngress += int64(meta.CaptureLength)
		s.ciIngress = &meta.CaptureInfo

		if s.lastPacketSeen.Before(s.ciIngress.Timestamp) {
			s.lastPacketSeen = s.ciIngress.Timestamp
		}
		f.updateStreamRecvStats(s.ciIngress, s.ciEgress)
		kIngress := icmpv6Key{netflow, kEgress.id, kEgress.seq}
		// Don't duplicate with traceroute print
		if typeCode.Type() == layers.ICMPv6TypeEchoReply {
			LogICMPv6(typeCode, kIngress.String(), s.ciEgress, packet)
		}
		s.done = true
		s.maybeFinish()
		f.delete(s)
	}
}

func (f *icmpv6StreamFactory) setLocalEnpoint(endpoint gopacket.Endpoint) {
	f.localEnpoint = endpoint
}

// collectOldStreams finds any streams that haven't received a packet within
// 'timeout'
func (f *icmpv6StreamFactory) collectOldStreams(timeout time.Duration) {
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

func (f *icmpv6StreamFactory) updateStreamRecvStats(ciIngress *gopacket.CaptureInfo, ciEgress *gopacket.CaptureInfo) {
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

func (f *icmpv6StreamFactory) showStats() {
	fmt.Fprintf(os.Stderr, "\n--- hpinggo statistic ---\n")
	fmt.Fprintf(os.Stderr, "%v packets tramitted, %v packets received\n",
		f.sentPackets, f.recvCount)
	fmt.Fprintf(os.Stderr, "round-trip min/avg/max = %v/%v/%v\n",
		time.Duration(f.rttMin)*time.Nanosecond,
		time.Duration(f.rttAvg)*time.Nanosecond,
		time.Duration(f.rttMax)*time.Nanosecond)
}
