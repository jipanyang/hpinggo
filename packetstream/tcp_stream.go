package packetstream

import (
	"context"
	"fmt"
	log "github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
	"github.com/jipanyang/hpinggo/options"
	"os"
	"strconv"
	"sync"
	"time"
)

// tcpStreamFactory implements reassembly.StreamFactory
// It also implement streamProtocolLayer interface
type tcpStreamFactory struct {
	ctx       context.Context
	streams   map[key]*tcpStream
	assembler *reassembly.Assembler

	localEnpoint gopacket.Endpoint
	// the RWMutex is for protecting recvCount (for now) which may be updated in waitPackets
	// and read in sendPackets
	mu sync.RWMutex
	// Number of packets sent, jumbo packet is counted as 1.
	sentPackets int64
	// Number of packets received, may be segmented.
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

// Create a new stream factory for tcp transport layer
func newTcpStreamFactory(ctx context.Context, opt options.Options) *tcpStreamFactory {
	f := &tcpStreamFactory{
		ctx:       ctx,
		streams:   make(map[key]*tcpStream),
		recvCount: 0,
		cmdOpts:   opt,
	}

	// Make the option setting available more conveniently
	f.parseOptions()
	// Set the starting point for dest and srouce ports
	f.dstPort = f.baseDestPort
	f.srcPort = uint16(opt.BaseSourcePort)

	// Set up assembly
	streamPool := reassembly.NewStreamPool(f)
	f.assembler = reassembly.NewAssembler(streamPool)

	// Limit memory usage by auto-flushing connection state if we get over 100K
	// packets in memory, or over 1000 for a single stream.
	f.assembler.MaxBufferedPagesTotal = 100000
	f.assembler.MaxBufferedPagesPerConnection = 1000

	return f
}

// tcpStreamFactory is used by assembly to create a new stream for each
// new TCP session which includes both incoming and outgoing flows.
// TODO: Make use of AssemblerContext and tcp *layers.TCP
func (f *tcpStreamFactory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
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
		log.V(2).Infof("[%v] found as first packet of TCP session in ingress direction", k)
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

func (f *tcpStreamFactory) delete(s *tcpStream) {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.streams, s.key) // remove it from our map.
}

func (f *tcpStreamFactory) parseOptions() {
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

func (f *tcpStreamFactory) prepareProtocalLayer(netLayer gopacket.NetworkLayer) gopacket.Layer {
	// Prepare for next call, this makes tcpStreamFactory stateful
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

	// TODO: populating the whole tcp layer every time, improve it?
	tcp := &layers.TCP{
		SrcPort: 0,
		DstPort: 0,
		FIN:     f.cmdOpts.TcpFin,
		SYN:     f.cmdOpts.TcpSyn,
		RST:     f.cmdOpts.TcpRst,
		PSH:     f.cmdOpts.TcpPush,
		ACK:     f.cmdOpts.TcpAck,
		URG:     f.cmdOpts.TcpUrg,
		ECE:     f.cmdOpts.TcpEce,
		CWR:     f.cmdOpts.TcpCwr,
		NS:      f.cmdOpts.TcpNs,
	}
	tcp.SetNetworkLayerForChecksum(netLayer)
	tcp.DstPort = layers.TCPPort(f.dstPort)
	tcp.SrcPort = layers.TCPPort(f.srcPort)
	return tcp
}

func (f *tcpStreamFactory) onSend(netLayer gopacket.NetworkLayer, transportLayer gopacket.Layer, payload []byte) {
	f.sentPackets += 1
	tcp := transportLayer.(*layers.TCP)
	tcp.SetInternalPortsForTesting()
	// pass the info to assembler so ingress flow may match it
	f.assembler.Assemble(netLayer.NetworkFlow(), tcp)
}

// TODO: check sequence number of each packet sent or received.
func (f *tcpStreamFactory) onReceive(packet gopacket.Packet) {
	log.V(7).Infof("%v", packet)
	if packet.NetworkLayer() == nil || packet.TransportLayer() == nil ||
		packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
		log.Errorf("Unusable packet: %v", packet)
		return
	}

	tcp := packet.TransportLayer().(*layers.TCP)
	f.assembler.Assemble(packet.NetworkLayer().NetworkFlow(), tcp)
}

func (f *tcpStreamFactory) setLocalEnpoint(endpoint gopacket.Endpoint) {
	f.localEnpoint = endpoint
}

// collectOldStreams finds any streams that haven't received a packet within
// 'timeout'
func (f *tcpStreamFactory) collectOldStreams(timeout time.Duration) {
	cutoff := time.Now().Add(-timeout)
	f.assembler.FlushCloseOlderThan(cutoff)

	// map iteration should be protected
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

func (f *tcpStreamFactory) updateStreamRecvStats(ciIngress *gopacket.CaptureInfo, ciEgress *gopacket.CaptureInfo) {
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

func (f *tcpStreamFactory) showStats() {
	fmt.Fprintf(os.Stderr, "\n--- hpinggo statistic ---\n")
	fmt.Fprintf(os.Stderr, "%v packets tramitted, %v packets received\n",
		f.sentPackets, f.recvCount)
	fmt.Fprintf(os.Stderr, "round-trip min/avg/max = %v/%v/%v\n",
		time.Duration(f.rttMin)*time.Nanosecond,
		time.Duration(f.rttAvg)*time.Nanosecond,
		time.Duration(f.rttMax)*time.Nanosecond)
}

// tcpStream implements reassembly.Stream
// TODO: Fix reassembly.Stream connection track issue in tcpStreamFactory
// TODO: Support UDP/ICMP and other protocols.
type tcpStream struct {
	key     key               // This is supposed to be client 2 server key, egress in our case.
	factory *tcpStreamFactory // Links back to stream factory

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
		s.factory.updateStreamRecvStats(s.ciIngress, s.ciEgress)
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
