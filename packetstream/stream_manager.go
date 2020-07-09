package packetstream

import (
	"context"
	"fmt"
	log "github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"github.com/google/gopacket/tcpassembly"
	"github.com/jipanyang/hpinggo/options"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

const (
	// timeout is the length of time to wait after last packet was sent.
	// TODO: change it to counterReachedTimeOut
	timeout time.Duration = time.Second * 5
)

// localEnpoint = layers.NewIPEndpoint(net.IP{1, 2, 3, 4}),

// key is used to map bidirectional streams to each other.
// should be applicable to TCP/UDP and other types of stream
// TODO: how about icmp which doesn't have endpoint type, maybe add extra field in key struct?
type key struct {
	net, transport gopacket.Flow
}

// String prints out the key in a human-readable fashion.
func (k key) String() string {
	return fmt.Sprintf("%v:%v", k.net, k.transport)
}

// packetStream implements tcpassembly.Stream
// TODO: Use reassembly.Stream which seems to be more feature rich?
// TODO: Support UDP/ICMP and other protocols.
type packetStream struct {
	bytes int64 // total bytes seen on this stream.
	bidi  *bidi // maps to the ingress and egress streams
	done  bool  // if true, we've seen the last packet we're going to for this stream.
}

// bidi stores each unidirectional side of a bidirectional stream.
type bidi struct {
	key             key           // Key of the first stream, mostly for logging.
	egress, ingress *packetStream // the two bidirectional streams.
	lastPacketSeen  time.Time     // last time we saw a packet from either stream.
	egressTriggered bool          // the stream is triggered by egress flow
}

// streamFactory implements tcpassmebly.StreamFactory
type streamFactory struct {
	// bidiMap maps keys to bidirectional stream pairs.
	bidiMap      map[key]*bidi
	recvCount    int64
	localEnpoint gopacket.Endpoint
}

// New handles creating a new tcpassembly.Stream.
// TODO: Use reassembly.Stream
func (f *streamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	// Create a new stream.
	s := &packetStream{}

	// Find the bidi bidirectional struct for this stream, creating a new one if
	// one doesn't already exist in the map.
	k := key{netFlow, tcpFlow}
	bd := f.bidiMap[k]
	isEgress := false
	if f.localEnpoint == netFlow.Src() {
		isEgress = true
	}
	if bd == nil {
		if isEgress {
			bd = &bidi{egress: s, key: k, egressTriggered: true}
			log.V(5).Infof("[%v] created egress side of bidirectional stream", bd.key)
		} else {
			bd = &bidi{ingress: s, key: k, egressTriggered: false}
			log.V(5).Infof("[%v] created ingresss side of bidirectional stream", bd.key)
		}
		// Register bidirectional with the reverse key, so the matching stream going
		// the other direction will find it.
		f.bidiMap[key{netFlow.Reverse(), tcpFlow.Reverse()}] = bd
	} else {
		if isEgress {
			// We capture ingress packets only,
			// egress packet is supposed to be earlier than its ingress counterpart
			log.Errorf("[%v] found egress side of bidirectional stream", bd.key)
			bd.egress = s
		} else {
			log.V(5).Infof("[%v] found ingress side of bidirectional stream", bd.key)
			bd.ingress = s
			f.recvCount += 1
		}
		// TODO: statistics of rtt, min/max/avg
		delete(f.bidiMap, k)
	}
	s.bidi = bd
	return s
}

// collectOldStreams finds any streams that haven't received a packet within
// 'timeout'
func (f *streamFactory) collectOldStreams() {
	cutoff := time.Now().Add(-timeout)
	for k, bd := range f.bidiMap {
		if bd.lastPacketSeen.Before(cutoff) {
			log.V(6).Infof("[%v] timing out old stream", bd.key)
			delete(f.bidiMap, k) // remove it from our map.
			bd.maybeFinish()     // Do something...?
		}
	}
}

// Reassembled handles reassembled TCP stream data.
func (s *packetStream) Reassembled(rs []tcpassembly.Reassembly) {
	for _, r := range rs {
		// For now, we'll simply count the bytes on each side of the TCP stream.
		s.bytes += int64(len(r.Bytes))
		if r.Skip > 0 {
			s.bytes += int64(r.Skip)
		}
		// Mark that we've received new packet data.
		// We could just use time.Now, but by using r.Seen we handle the case
		// where packets are being read from a file and could be very old.
		if s.bidi.lastPacketSeen.Before(r.Seen) {
			s.bidi.lastPacketSeen = r.Seen
		}
	}
}

// ReassemblyComplete marks this stream as finished.
func (s *packetStream) ReassemblyComplete() {
	s.done = true
	s.bidi.maybeFinish()
}

// maybeFinish print out stats.
// TODO: do something more meaningful.
func (bd *bidi) maybeFinish() {
	switch {
	case bd.egress == nil:
		log.V(5).Infof("Egress missing: [%v]", bd)
	case !bd.egress.done:
		log.V(5).Infof("still waiting on first egress stream: [%v] ", bd)
	case bd.ingress == nil:
		log.V(5).Infof("Ingress missing: [%v]", bd)
	case !bd.ingress.done:
		log.V(5).Infof("still waiting on first ingress stream: [%v] ", bd)
	default:
		log.V(5).Infof("[%v] FINISHED, bytes: %d tx, %d rx", bd.key, bd.egress.bytes, bd.ingress.bytes)
	}
}

type packetStreamMgmr struct {
	ctx context.Context
	// iface is the interface to send packets on.
	iface *net.Interface
	// destination, gateway (if applicable), and source IP addresses to use.
	// Note, they will be overrided if corresponding RandDest or RandSource option is set.
	dst, gw, src net.IP

	handle   *pcap.Handle
	socketFd int // fd of raw socket
	ipConn   net.PacketConn

	// opts and buf allow us to easily serialize packets in the send()
	// method.
	packetOpts gopacket.SerializeOptions
	buf        gopacket.SerializeBuffer

	streamFactory *streamFactory
	assembler     *tcpassembly.Assembler

	// options specified at user command line
	cmdOpts options.Options
	// convenient variables derived from options
	baseDestPort     uint16
	incDestPort      bool
	forceIncDestPort bool
}

func NewPacketStreamMgmr(ctxParent context.Context, dstIp net.IP, fd int, opt options.Options) (*packetStreamMgmr, error) {
	m := &packetStreamMgmr{
		ctx:      ctxParent,
		dst:      dstIp,
		socketFd: fd,
		packetOpts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf:     gopacket.NewSerializeBuffer(),
		cmdOpts: opt,
	}

	// Make the option setting available more conveniently
	m.parseOptions()
	// Set up assembly
	m.streamFactory = &streamFactory{bidiMap: make(map[key]*bidi), recvCount: 0}
	streamPool := tcpassembly.NewStreamPool(m.streamFactory)
	m.assembler = tcpassembly.NewAssembler(streamPool)
	// Limit memory usage by auto-flushing connection state if we get over 100K
	// packets in memory, or over 1000 for a single stream.
	m.assembler.MaxBufferedPagesTotal = 100000
	m.assembler.MaxBufferedPagesPerConnection = 1000

	if !dstIp.IsUnspecified() {
		// Figure out the route to the IP.
		// TODO: gopacket router will crash if no default ipv6 route  available, fix it.
		router, err := routing.New()
		if err != nil {
			log.Fatal("routing error:", err)
		}
		iface, gw, src, err := router.Route(dstIp)
		if err != nil {
			return nil, err
		}
		log.Infof("Streaming to dstIp %v with interface %v, gateway %v, src %v\n cmdOpts %+v",
			dstIp, iface.Name, gw, src, m.cmdOpts)
		m.gw, m.src, m.iface = gw, src, iface

		m.streamFactory.localEnpoint = layers.NewIPEndpoint(src)
	}

	m.open_pcap()

	return m, nil
}

func (m *packetStreamMgmr) parseOptions() {
	destPortStr := m.cmdOpts.DestPort
	if destPortStr[:1] == "+" {
		m.incDestPort = true
		destPortStr = destPortStr[1:]
	}
	if destPortStr[:1] == "+" {
		m.forceIncDestPort = true
		destPortStr = destPortStr[1:]
	}

	port, err := strconv.Atoi(destPortStr)
	if err != nil {
		log.Exitf("Invalid dest port: %v, %v\n", m.cmdOpts.DestPort, err)
	}
	m.baseDestPort = uint16(port)
}

func (m *packetStreamMgmr) open_pcap() {
	var ifName string

	if m.cmdOpts.Interface != "" {
		ifName = m.cmdOpts.Interface
	} else {
		ifName = m.iface.Name
	}

	// Open up a pcap handle for packet reads.
	handle, err := pcap.OpenLive(ifName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Exitf("error creating a pcap handle: %v\n", err)
	}
	log.Infof("Opened pcap handle %+v", handle)
	m.handle = handle

	// TODO: support other protocals
	// TODO: Fix first ingress packet drop issue
	// https://www.pico.net/kb/how-does-one-use-tcpdump-to-capture-incoming-traffic
	bpffilter := fmt.Sprintf("inbound and tcp")
	log.Infof("Using BPF filter %q\n", bpffilter)
	if err := m.handle.SetBPFFilter(bpffilter); err != nil {
		log.Exitf("SetBPFFilter: %v\n", err)
	}
}

// Raw socket send
func (m *packetStreamMgmr) rawSockSend(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(m.buf, m.packetOpts, l...); err != nil {
		return err
	}
	packetData := m.buf.Bytes()

	ip := []byte(m.dst)

	if !m.cmdOpts.Ipv6 {

		var dstIp [4]byte
		copy(dstIp[:], ip[:4])

		addr := syscall.SockaddrInet4{
			Port: 0,
			Addr: dstIp,
		}
		err := syscall.Sendto(m.socketFd, packetData, 0, &addr)
		if err != nil {
			log.Fatal("Sendto:", err)
		}
	} else {
		var dstIp [16]byte
		copy(dstIp[:], ip[:16])

		addr := syscall.SockaddrInet6{
			Port: 0,
			Addr: dstIp,
		}
		err := syscall.Sendto(m.socketFd, packetData, 0, &addr)
		if err != nil {
			log.Fatal("Sendto:", err)
		}
	}
	return nil
}

func (m *packetStreamMgmr) waitPackets(stop chan struct{}) {
	packetSrc := gopacket.NewPacketSource(m.handle, layers.LayerTypeEthernet)
	in := packetSrc.Packets()

	ticker := time.Tick(timeout / 4)
	for {
		select {
		case packet := <-in:

			log.V(7).Infof("%v", packet)
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Errorf("Unusable packet: %v", packet)
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			m.assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// flush connections that haven't seen activity in the past timeout duration.
			log.Infof("---- FLUSHING ----")
			m.assembler.FlushOlderThan(time.Now().Add(-timeout))
			m.streamFactory.collectOldStreams()
		case <-stop:
			return
		}
	}
}

func (m *packetStreamMgmr) sendPackets(netLayer gopacket.NetworkLayer, transportLayer gopacket.TransportLayer) error {
	// TODO: support rand dest and rand source.
	// TODO: support raw IP, icmp and UDP
	// TODO: support varying packet data content and size
	sentPackets := 0
	// TODO: Support more transport layer. Assuming TCP only for now.
	tcp := transportLayer.(*layers.TCP)
	// TODO: Support --destport [+][+]dest port
	dstPort := m.baseDestPort

	defer func() {
		fmt.Fprintf(os.Stderr, "\n--- hpinggo statistic ---\n")
		fmt.Fprintf(os.Stderr, "%v packets tramitted, %v packets received\n", sentPackets, m.streamFactory.recvCount)
	}()

	for {
		tcp.DstPort = layers.TCPPort(dstPort)

		switch v := netLayer.(type) {
		case *layers.IPv4:
			if err := m.rawSockSend(v, tcp); err != nil {
				log.Errorf("error raw socket sending to port %v: %v", tcp.DstPort, err)
			}
			tcp.SetInternalPortsForTesting()
			// pass the info to assembler
			m.assembler.AssembleWithTimestamp(v.NetworkFlow(), tcp, time.Now())
		case *layers.IPv6:
			if err := m.rawSockSend(v, tcp); err != nil {
				log.Errorf("error raw socket sending to port %v: %v", tcp.DstPort, err)
			}
			// pass the info to assembler
			m.assembler.AssembleWithTimestamp(v.NetworkFlow(), tcp, time.Now())
		default:
			return fmt.Errorf("cannot use layer type %v for tcp checksum network layer", netLayer.LayerType())
		}

		dstPort += 1
		sentPackets += 1
		if sentPackets == m.cmdOpts.Count {
			log.Infof("Sent %v packets, exiting in 1 second", sentPackets)
			time.Sleep(1 * time.Second)

			return nil
		}
		select {
		case <-time.After(m.cmdOpts.Interval):
			continue
		case <-m.ctx.Done():
			fmt.Fprintf(os.Stderr, "Asked to terminiate early \n")
			return nil
		}
	}
}

func (m *packetStreamMgmr) Stream() error {
	// TODO: support for UDP, ICMP, ....
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(m.cmdOpts.BaseSourcePort),
		DstPort: 0, // will be incremented during the scan
		FIN:     m.cmdOpts.TcpFin,
		SYN:     m.cmdOpts.TcpSyn,
		RST:     m.cmdOpts.TcpRst,
		PSH:     m.cmdOpts.TcpPush,
		ACK:     m.cmdOpts.TcpAck,
		URG:     m.cmdOpts.TcpUrg,
		ECE:     m.cmdOpts.TcpEce,
		CWR:     m.cmdOpts.TcpCwr,
		NS:      m.cmdOpts.TcpNs,
	}

	// var networkLayer gopacket.NetworkLayer
	var ipv6 layers.IPv6
	var ipv4 layers.IPv4
	if m.cmdOpts.Ipv6 {
		ipv6 = layers.IPv6{
			SrcIP:      m.src,
			DstIP:      m.dst,
			Version:    6,
			HopLimit:   255,
			NextHeader: layers.IPProtocolTCP,
		}
		tcp.SetNetworkLayerForChecksum(&ipv6)
	} else {
		ipv4 = layers.IPv4{
			SrcIP:    m.src,
			DstIP:    m.dst,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		tcp.SetNetworkLayerForChecksum(&ipv4)
	}

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go m.waitPackets(stop)
	defer close(stop)
	log.Infof("Start Streaming, time: %v", time.Now())
	if m.cmdOpts.Ipv6 {
		m.sendPackets(&ipv6, &tcp)
	} else {
		m.sendPackets(&ipv4, &tcp)
	}

	log.Infof("Return from Stream, socketFd: %v, time: %v", m.socketFd, time.Now())
	return nil
}

func (m *packetStreamMgmr) Close() {
	// remove the filter to get any packet to get out of handle.getNextBufPtrLocked()
	// Otherwise pcap handle will wait for packet which matches the filter.
	if err := m.handle.SetBPFFilter(""); err != nil {
		log.Exitf("SetBPFFilter: %v\n", err)
	}
	m.handle.Close()
}
