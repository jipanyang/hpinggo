package packetstream

import (
	"context"
	"fmt"
	log "github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/jipanyang/hpinggo/options"
	"os"
	"sync"
	"time"
)

// for tracking icmp request and reply
// ICMPv4TypeEchoRequest
// ICMPv4TypeTimestampRequest
// ICMPv4TypeInfoRequest
// ICMPv4TypeAddressMaskRequest
// Not supporting other ICMP type like ICMPv4TypeDestinationUnreachable/ICMPv4TypeRedirect
type icmpKey struct {
	net gopacket.Flow
	id  uint16
	seq uint16
}

// String prints out the key in a human-readable fashion.
func (k icmpKey) String() string {
	return fmt.Sprintf("%v:%v:%v", k.net, k.id, k.seq)
}

// icmpStream
type icmpStream struct {
	key                              icmpKey               // This is supposed to be client 2 server key, egress in our case.
	bytesEgress, bytesIngress, bytes int64                 // Total bytes seen on this stream.
	ciEgress, ciIngress              *gopacket.CaptureInfo // To store the CaptureInfo seen on first packet of each direction
	lastPacketSeen                   time.Time             // last time we saw a packet from either stream.
	done                             bool                  // if true, we've seen the last packet we're going to for this stream.
}

// maybeFinish print out stats.
// TODO: do something more meaningful.
func (s *icmpStream) maybeFinish() {
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

// icmpStreamFactory implements reassembly.StreamFactory
// It also implement streamProtocolLayer interface
type icmpStreamFactory struct {
	ctx     context.Context
	streams map[icmpKey]*icmpStream

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
}

// Create a new stream factory for ICMP transport layer
func newIcmpStreamFactory(ctx context.Context, opt options.Options) *icmpStreamFactory {
	f := &icmpStreamFactory{
		ctx:       ctx,
		streams:   make(map[icmpKey]*icmpStream),
		recvCount: 0,
		cmdOpts:   opt,
	}

	// Make the option setting available more conveniently
	f.parseOptions()
	// Set the starting point for dest and srouce ports
	f.id = uint16(os.Getppid())
	f.seq = 0

	return f
}

func (f *icmpStreamFactory) delete(s *icmpStream) {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.streams, s.key) // remove it from our map.
}

func (f *icmpStreamFactory) parseOptions() {

}

// gopacket classify icmpv4/icmpv6 as LayerClassIPControl
func (f *icmpStreamFactory) prepareProtocalLayer(netLayer gopacket.NetworkLayer) gopacket.Layer {
	f.seq++

	// TODO: populating the whole udp layer every time, improve it?
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(uint8(f.cmdOpts.IcmpType), uint8(f.cmdOpts.IcmpCode)),
		Id:       f.id,
		Seq:      f.seq,
	}
	// icmp.SetNetworkLayerForChecksum(netLayer)

	switch v := netLayer.(type) {
	case *layers.IPv4:
		v.Protocol = layers.IPProtocolICMPv4
	// case *layers.IPv6:
	// 	v.NextHeader = layers.IPProtocolICMPv6
	default:
		panic("Unsupported network layer value")
	}

	return icmp
}

func (f *icmpStreamFactory) onSend(netLayer gopacket.NetworkLayer, icmpLayer gopacket.Layer, payload []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sentPackets += 1

	netFlow := netLayer.NetworkFlow()

	icmp := icmpLayer.(*layers.ICMPv4)
	// icmpType := icmp.TypeCode.Type()
	// icmpCode := icmp.TypeCode.Code()

	k := icmpKey{netFlow, icmp.Id, icmp.Seq}
	if f.streams[k] != nil {
		log.Infof("[%v] found existing stream", k)
		f.streams[k].lastPacketSeen = time.Now()
		return
	}

	// Fake CaptureInfo since we don't capture on egress
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: (len(payload)) + 8, // what is the length of icmp/ip/ether headers?
		Length:        (len(payload)) + 8,
	}
	s := &icmpStream{key: k, ciEgress: &ci, lastPacketSeen: ci.Timestamp}
	f.streams[k] = s

	log.V(5).Infof("[%v] created ICMP session", k)

}

// TODO: check sequence number of each packet sent or received.
func (f *icmpStreamFactory) onReceive(packet gopacket.Packet) {
	log.V(7).Infof("%v", packet)

	if packet.NetworkLayer() == nil {
		log.Errorf("Unusable packet: %v", packet)
		return
	}
	icmp, ok := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if !ok {
		log.Errorf("Unusable packet: %v", packet)
		return
	}
	netflow := packet.NetworkLayer().NetworkFlow()

	kEgress := icmpKey{netflow.Reverse(), icmp.Id, icmp.Seq}
	// Found ingress flow for the corresponding egress flow.
	s := f.streams[kEgress]
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
	} else {
		log.V(5).Infof("[%v] not found", kEgress)
	}
}

func (f *icmpStreamFactory) setLocalEnpoint(endpoint gopacket.Endpoint) {
	f.localEnpoint = endpoint
}

// collectOldStreams finds any streams that haven't received a packet within
// 'timeout'
func (f *icmpStreamFactory) collectOldStreams(timeout time.Duration) {
	cutoff := time.Now().Add(-timeout)

	for k, s := range f.streams {
		if s.lastPacketSeen.Before(cutoff) {
			log.V(5).Infof("[%v] timing out old session", s.key)
			delete(f.streams, k) // remove it from our map.
			s.maybeFinish()      // Do something...?
		}
	}
}

func (f *icmpStreamFactory) updateStreamRecvStats(ciIngress *gopacket.CaptureInfo, ciEgress *gopacket.CaptureInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
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

func (f *icmpStreamFactory) showStats() {
	fmt.Fprintf(os.Stderr, "\n--- hpinggo statistic ---\n")
	fmt.Fprintf(os.Stderr, "%v packets tramitted, %v packets received\n",
		f.sentPackets, f.recvCount)
	fmt.Fprintf(os.Stderr, "round-trip min/avg/max = %v/%v/%v\n",
		time.Duration(f.rttMin)*time.Nanosecond,
		time.Duration(f.rttAvg)*time.Nanosecond,
		time.Duration(f.rttMax)*time.Nanosecond)
}
