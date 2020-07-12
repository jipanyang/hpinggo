package packetstream

import (
	"context"
	"fmt"
	log "github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
	"github.com/google/gopacket/routing"
	"github.com/jipanyang/hpinggo/options"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// timeout is the length of time to wait after last packet was sent.
	// TODO: change it to counterReachedTimeOut
	timeout time.Duration = time.Second * 5
)

// key is used to identify a TCP session with c2s info.
// should be applicable to TCP/UDP and other types of stream
// TODO: how about icmp which doesn't have endpoint type, maybe add extra field in key struct?
type key struct {
	net, transport gopacket.Flow
}

// String prints out the key in a human-readable fashion.
func (k key) String() string {
	return fmt.Sprintf("%v:%v", k.net, k.transport)
}

// packetStream implements reassembly.Stream amd tcpassembly/Strea,
// TODO: Fix reassembly.Stream connection track issue in streamFactory
// TODO: Support UDP/ICMP and other protocols.
type packetStream struct {
	key     key            // This is supposed to be client 2 server key, egress in our case.
	factory *streamFactory // Links back to stream factory

	bytesEgress, bytesIngress, bytes int64                 // Total bytes seen on this stream.
	ciEgress, ciIngress              *gopacket.CaptureInfo // To stor the CaptureInfo seen on first packet of each direction
	lastPacketSeen                   time.Time             // last time we saw a packet from either stream.
	done                             bool                  // if true, we've seen the last packet we're going to for this stream.
}

// streamFactory implements tcpassmebly.StreamFactory
type streamFactory struct {
	streams map[key]*packetStream

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
	s := &packetStream{key: k, ciEgress: &ci, factory: f}
	f.streams[k] = s

	log.V(5).Infof("[%v] created TCP session", k)
	return s
}

func (f *streamFactory) delete(s *packetStream) {
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

func (s *packetStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
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
func (s *packetStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	bytes, _ := sg.Lengths()
	s.bytes += int64(bytes)

	// GetCaptureInfo() gopacket.CaptureInfo
	c := ac.GetCaptureInfo()
	if s.lastPacketSeen.Before(c.Timestamp) {
		s.lastPacketSeen = c.Timestamp
	}
}

func (s *packetStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	// TODO: make use of AssemblerContext
	s.done = true
	s.maybeFinish()
	s.factory.delete(s)
	return true
}

// maybeFinish print out stats.
// TODO: do something more meaningful.
func (s *packetStream) maybeFinish() {
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

// TODO: more comprehensive sanity check
func randIpSanityCheck(ipStr string, isIPv6 bool) bool {
	if !isIPv6 {
		octets := strings.Split(ipStr, ".")
		if len(octets) != net.IPv4len {
			return false
		}
	} else {
		twoOctets := strings.Split(ipStr, ":")
		if len(twoOctets) < 2 || len(twoOctets) > net.IPv6len/2 {
			return false
		}
	}
	return true
}

// Get one
func getRandomIPv4(randDest string) net.IP {
	octets := strings.Split(randDest, ".")
	ipStr := ""
	for _, octet := range octets {
		if octet == "x" {
			ipStr += strconv.Itoa(rand.Intn(256)) + "."
		} else {
			ipStr += octet + "."
		}
	}
	last := len(ipStr) - 1
	ipStr = ipStr[:last]
	return net.ParseIP(ipStr)
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
	assembler     *reassembly.Assembler

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
	m.streamFactory = &streamFactory{streams: make(map[key]*packetStream), recvCount: 0}
	streamPool := reassembly.NewStreamPool(m.streamFactory)
	m.assembler = reassembly.NewAssembler(streamPool)

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
		log.Infof("Streaming to destination %v with interface %v, gateway %v, src %v\n cmdOpts %+v",
			dstIp, iface.Name, gw, src, m.cmdOpts)
		m.gw, m.src, m.iface = gw, src, iface

		m.streamFactory.localEnpoint = layers.NewIPEndpoint(src)
	} else {
		if !randIpSanityCheck(opt.RandDest, opt.IPv6) {
			log.Exitf("Invalid random IP %v\n", opt.RandDest)
		}
		// The interface has to be specificed.
		if opt.Interface == "" {
			log.Exitf("Should specify interface in rand-dest mode\n")
		}
		iface, err := net.InterfaceByName(opt.Interface)
		if err != nil {
			log.Exitf("Invalid interface name: %v\n", err)
		}
		ifAddrs, err := iface.Addrs()
		if err != nil {
			log.Exitf("Interface: %v %v\n", iface, err)
		} else {
			log.Infof("Interface: %v, Addresses: %v\n", iface, ifAddrs)
		}
		m.iface = iface
		// TODO: IsGlobalUnicast() vs IsLinkLocalUnicast()?
		for _, addr := range ifAddrs {
			src := addr.(*net.IPNet).IP
			if src.To4() != nil && !opt.IPv6 {
				m.src = src
				break
			}
			if src.To4() == nil && src.To16() != nil && opt.IPv6 {
				m.src = src
				break
			}
		}
		log.Infof("  Streaming to destination %v with interface %v, src %v\n  cmdOpts %+v",
			opt.RandDest, m.iface.Name, m.src, m.cmdOpts)
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

	var ip net.IP
	switch v := l[0].(type) {
	case *layers.IPv4:
		ip = v.DstIP
	case *layers.IPv6:
		ip = v.DstIP
	}

	if !m.cmdOpts.IPv6 {
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

			// ctx := packet.Metadata()
			// m.assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, ctx)
			m.assembler.Assemble(packet.NetworkLayer().NetworkFlow(), tcp)

		case <-ticker:
			// flush connections that haven't seen activity in the past timeout duration.
			log.Infof("---- FLUSHING ----")

			m.assembler.FlushCloseOlderThan(time.Now().Add(-timeout))
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
	srcPort := m.cmdOpts.BaseSourcePort

	var payload []byte
	if m.cmdOpts.Data > 0 {
		payload = make([]byte, m.cmdOpts.Data)
		for i := range payload {
			payload[i] = 0xfe
		}
	}

	defer func() {
		fmt.Fprintf(os.Stderr, "\n--- hpinggo statistic ---\n")
		fmt.Fprintf(os.Stderr, "%v packets tramitted, %v packets received\n",
			sentPackets, m.streamFactory.recvCount)
		fmt.Fprintf(os.Stderr, "round-trip min/avg/max = %v/%v/%v\n",
			time.Duration(m.streamFactory.rttMin)*time.Nanosecond,
			time.Duration(m.streamFactory.rttAvg)*time.Nanosecond,
			time.Duration(m.streamFactory.rttMax)*time.Nanosecond)
	}()

	for {
		tcp.DstPort = layers.TCPPort(dstPort)
		tcp.SrcPort = layers.TCPPort(srcPort)

		switch v := netLayer.(type) {
		case *layers.IPv4:
			if m.cmdOpts.RandDest != "" {
				v.DstIP = getRandomIPv4(m.cmdOpts.RandDest)
				if v.DstIP == nil {
					panic("Failed to get random IP")
				}
			}
			if m.cmdOpts.RandSource != "" {
				v.SrcIP = getRandomIPv4(m.cmdOpts.RandSource)
				if v.SrcIP == nil {
					panic("Failed to get random IP")
				}
			}
			if err := m.rawSockSend(v, tcp, gopacket.Payload(payload)); err != nil {
				log.Errorf("error raw socket sending %v->%v: %v", tcp.SrcPort, tcp.DstPort, err)
			}
			tcp.SetInternalPortsForTesting()
			// pass the info to assembler so ingress flow may match it

			m.assembler.Assemble(v.NetworkFlow(), tcp)

		case *layers.IPv6:
			if err := m.rawSockSend(v, tcp, gopacket.Payload(payload)); err != nil {
				log.Errorf("error raw socket sending %v->%v: %v", tcp.SrcPort, tcp.DstPort, err)
			}
			// pass the info to assembler so ingress flow may match it

			m.assembler.Assemble(v.NetworkFlow(), tcp)

		default:
			return fmt.Errorf("cannot use layer type %v for tcp checksum network layer", netLayer.LayerType())
		}
		if m.forceIncDestPort {
			dstPort += 1
		} else if m.incDestPort {
			m.streamFactory.mu.RLock()
			dstPort = m.baseDestPort + uint16(m.streamFactory.recvCount)
			m.streamFactory.mu.RUnlock()
		}

		sentPackets += 1
		if sentPackets == m.cmdOpts.Count {
			log.Infof("Sent %v packets, exiting in 1 second", sentPackets)
			time.Sleep(1 * time.Second)
			return nil
		}

		// Update source port number unless asked to stay const
		if !m.cmdOpts.KeepConstSourcePort {
			srcPort = (sentPackets + m.cmdOpts.BaseSourcePort) % 65536
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

func (m *packetStreamMgmr) StartStream() error {
	// TODO: support for UDP, ICMP, ....
	tcp := layers.TCP{
		SrcPort: 0,
		DstPort: 0,
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
	if m.cmdOpts.IPv6 {
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
	if m.cmdOpts.IPv6 {
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
