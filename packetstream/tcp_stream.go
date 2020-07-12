package packetstream

import (
	log "github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"sync"
	"time"
)

// streamFactory implements reassembly.StreamFactory
type streamFactory struct {
	streams map[key]*tcpStream

	localEnpoint gopacket.Endpoint
	// the RWMutex is for protecting recvCount (for now) which may be updated in waitPackets
	// and read in sendPackets
	mu                     sync.RWMutex
	recvCount              int64
	rttMin, rttMax, rttAvg int64
}

// streamFactory is used by assembly to create a new stream for each
// new TCP session which includes both incoming and outgoing flows.
// TODO: Make use of AssemblerContext and tcp *layers.TCP
func (f *streamFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	f.mu.Lock()
	defer f.mu.Unlock()
	// This is the first packet seen for the tcp session, should be in direction of client to server.
	// In our case, egress flow
	k := key{netFlow, tcpFlow}
	if f.streams[k] != nil {
		log.Errorf("[%v] found existing stream", k)
		return f.streams[k]
	}

	// We deal with session initiated from our side.
	isEgress := true
	if f.localEnpoint != netFlow.Src() {
		isEgress = false
	}
	if !isEgress {
		log.Infof("[%v] found as first packet of TCP session in ingress direction", k)
		// TODO: update gopacket/reassembly so it is possible to ignore certain flows.
		// return nil
	}

	// Create a new stream.
	ci := ac.GetCaptureInfo()
	s := &tcpStream{key: k, ciEgress: &ci, factory: f}
	f.streams[k] = s

	log.V(5).Infof("[%v] created TCP session", k)
	return s
}

func (f *streamFactory) delete(s *tcpStream) {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.streams, s.key) // remove it from our map.
}

// collectOldStreams finds any streams that haven't received a packet within
// 'timeout'
func (f *streamFactory) collectOldStreams() {
	cutoff := time.Now().Add(-timeout)
	for k, s := range f.streams {
		if s.lastPacketSeen.Before(cutoff) {
			log.V(6).Infof("[%v] timing out old session", s.key)
			delete(f.streams, k) // remove it from our map.
			s.maybeFinish()      // Do something...?
		}
	}
}

func (f *streamFactory) updateRecvStats(ciIngress *gopacket.CaptureInfo, ciEgress *gopacket.CaptureInfo) {
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

// tcpStream implements reassembly.Stream amd tcpassembly/Strea,
// TODO: Fix reassembly.Stream connection track issue in streamFactory
// TODO: Support UDP/ICMP and other protocols.
type tcpStream struct {
	key     key            // This is supposed to be client 2 server key, egress in our case.
	factory *streamFactory // Links back to stream factory

	bytesEgress, bytesIngress, bytes int64                 // Total bytes seen on this stream.
	ciEgress, ciIngress              *gopacket.CaptureInfo // To stor the CaptureInfo seen on first packet of each direction
	lastPacketSeen                   time.Time             // last time we saw a packet from either stream.
	done                             bool                  // if true, we've seen the last packet we're going to for this stream.
}

func (s *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// Tell whether the TCP packet should be accepted, start could be modified to force a start even if no SYN have been seen
	// TODO: make use of it
	if dir == reassembly.TCPDirClientToServer {
		return true
	}
	if s.ciIngress == nil {
		s.ciIngress = &ci
		// update received session count.
		// TODO: add RTT statistics for session based on CaptureInfo
		s.factory.updateRecvStats(s.ciIngress, s.ciEgress)
		log.V(5).Infof("[%v]: The opposite ingress packet arrived", s.key)
	}

	return true
}

// TODO: add direction to the ReassembledSG() interface
func (s *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	bytes, _ := sg.Lengths()
	s.bytes += int64(bytes)

	// GetCaptureInfo() gopacket.CaptureInfo
	c := ac.GetCaptureInfo()
	if s.lastPacketSeen.Before(c.Timestamp) {
		s.lastPacketSeen = c.Timestamp
	}
}

func (s *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	// TODO: make use of AssemblerContext
	s.done = true
	s.maybeFinish()
	s.factory.delete(s)
	return true
}

// maybeFinish print out stats.
// TODO: do something more meaningful.
func (s *tcpStream) maybeFinish() {
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
