package packetstream

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	log "github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"github.com/jipanyang/hpinggo/options"
	"github.com/jipanyang/hpinggo/utilities"
)

const (
	// timeout is the length of time to wait after last packet was sent.
	// TODO: change it to counterReachedTimeOut
	timeout time.Duration = time.Second * 5
)

// Interface for protocol layer stream processing.
// Assuming the protocol runs above IP layer immediately,
// Could be TransportLayer protocols lik TCP/UDP or control protocols like ICMPv4/ICMPv6
type StreamProtocolLayer interface {
	// Prepare protocol layer before it could be serialized to wire format
	PrepareProtocalLayers(gopacket.NetworkLayer) []gopacket.Layer
	// Post processing after the packet is sent.
	OnSend(gopacket.NetworkLayer, []gopacket.Layer, []byte)
	// Post processing after a packet is received.
	OnReceive(gopacket.Packet)

	// Inform trasport layer of its local end point for checking flow direction.
	SetLocalEnpoint(gopacket.Endpoint)

	CollectOldStreams(time.Duration)

	ShowStats()
}

// key is used to identify a TCP session with c2s info.
// Applicable to TCP/UDP stream
type key struct {
	net, transport gopacket.Flow
}

// String prints out the key in a human-readable fashion.
func (k key) String() string {
	// return fmt.Sprintf("%v :: %v", k.net, k.transport)
	return fmt.Sprintf("%v:%v->%v:%v", k.net.Src(), k.transport.Src(), k.net.Dst(), k.transport.Dst())
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

// Get one random IPv4 IP based on the string pattern
// Ex.  x.x.x.x 192.168.1.x,  192.x.1.1
func getRandomIPv4(randIP string) (ip net.IP) {
	randIP = strings.TrimSpace(randIP)
	octets := strings.Split(randIP, ".")
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
	ip = net.ParseIP(ipStr)
	log.V(2).Infof("Got random IP %s: %v\n", ipStr, ip)
	return
}

func getRandomIPv6(randIP string) (ip net.IP) {
	randIP = strings.TrimSpace(randIP)
	halves := strings.Split(randIP, "::")
	ipStr := ""
	for _, half := range halves {
		hextets := strings.Split(half, ":")
		for _, hextet := range hextets {
			if hextet == "x" {
				ipStr += fmt.Sprintf("%x", rand.Intn(256)) + ":"
			} else if hextet == "xx" {
				ipStr += fmt.Sprintf("%x", rand.Intn(65536)) + ":"
			} else {
				ipStr += hextet + ":"
			}
		}
		last := len(ipStr) - 1
		ipStr = ipStr[:last]
		ipStr += "::"
	}
	last := len(ipStr) - 2
	ipStr = ipStr[:last]
	log.V(2).Infof("Got random IP %s: %v\n", ipStr, ip)
	return
}

// TODO: move some options from NewPacketStreamMgmr to here
type PacketStreamMgmr interface {
	StartStream() error
	Close()
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

	streamFactory StreamProtocolLayer

	// options specified at user command line
	cmdOpts options.Options
}

func NewPacketStreamMgmr(ctx context.Context, dstIp net.IP, opt options.Options) (*packetStreamMgmr, error) {
	m := &packetStreamMgmr{
		ctx: ctx,
		dst: dstIp,
		packetOpts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf:     gopacket.NewSerializeBuffer(),
		cmdOpts: opt,
	}

	var err error
	if opt.IPv6 {
		m.socketFd, err = utilities.OpenRawSocket(unix.AF_INET6)
	} else {
		m.socketFd, err = utilities.OpenRawSocket(unix.AF_INET)
	}
	if err != nil {
		return nil, err
	}

	if opt.Icmp {
		if opt.IPv6 {
			m.streamFactory = newIcmpv6StreamFactory(ctx, opt)
		} else {
			m.streamFactory = newIcmpv4StreamFactory(ctx, opt)
		}
	} else if opt.Udp {
		m.streamFactory = newUdpStreamFactory(ctx, opt)
	} else {
		m.streamFactory = newTcpStreamFactory(ctx, opt)
	}

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
		log.Infof("StreamMgmr for destination %v with interface %v, gateway %v, src %v\n",
			dstIp, iface.Name, gw, src)
		m.gw, m.src, m.iface = gw, src, iface
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
			log.V(1).Infof("Interface: %v, Addresses: %v\n", iface, ifAddrs)
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
		log.Infof("StreamMgmr for destination %v with interface %v, src %v\n",
			opt.RandDest, m.iface.Name, m.src)
	}
	m.streamFactory.SetLocalEnpoint(layers.NewIPEndpoint(m.src))
	m.open_pcap()

	return m, nil
}

func (m *packetStreamMgmr) parseOptions() {
	//TODO: add as needed
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
	log.V(1).Infof("Opened pcap handle %+v", handle)
	m.handle = handle

	// TODO: support other protocals
	// TODO: Fix first ingress packet drop issue
	// https://www.pico.net/kb/how-does-one-use-tcpdump-to-capture-incoming-traffic
	var bpffilter string
	ip := "ip"
	icmp := "icmp"
	if m.cmdOpts.IPv6 {
		icmp = "icmp6"
		ip = "ip6"
	}
	if m.cmdOpts.Udp {
		// bpffilter = fmt.Sprintf("udp or %s and %s and inbound", icmp, ip)
		bpffilter = fmt.Sprintf("udp or %s and %s", icmp, ip)
	} else if m.cmdOpts.Icmp {
		// bpffilter = fmt.Sprintf("%s and inbound", icmp)
		bpffilter = fmt.Sprintf("%s", icmp)
	} else {
		// bpffilter = fmt.Sprintf("tcp or %s and %s and inbound", icmp, ip)
		bpffilter = fmt.Sprintf("tcp or %s and %s", icmp, ip)
	}

	log.V(1).Infof("Using BPF filter %q\n", bpffilter)
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
	// p := gopacket.NewPacket(packetData, layers.LayerTypeIPv6, gopacket.Default)
	// log.V(5).Infof("NewPacket: [%v]", p)

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
			m.streamFactory.OnReceive(packet)
		case <-ticker:
			// flush connections that haven't seen activity in the past timeout duration.
			log.V(1).Infof("---- FLUSHING ----")
			m.streamFactory.CollectOldStreams(timeout)

		case <-stop:
			log.Warningf("Asked to stop\n")
			log.Infof("streamFactory:%T %+v\n", m.streamFactory, m.streamFactory)
			return
		}
	}
}

func (m *packetStreamMgmr) sendPackets(netLayer gopacket.NetworkLayer) error {
	// TODO: support raw IP, icmp and UDP
	// TODO: support varying packet data content and size
	sentPackets := 0

	var payload []byte
	if m.cmdOpts.Data > 0 {
		payload = make([]byte, m.cmdOpts.Data)
		for i := range payload {
			payload[i] = 0xfe
		}
	}

	defer m.streamFactory.ShowStats()
	defer log.Flush()
	log.Infof("streamFactory:%T %+v\n", m.streamFactory, m.streamFactory)
	for {
		protoLayers := m.streamFactory.PrepareProtocalLayers(netLayer)
		switch v := netLayer.(type) {
		case *layers.IPv4:
			if m.cmdOpts.RandDest != "" {
				v.DstIP = getRandomIPv4(m.cmdOpts.RandDest)
				if v.DstIP == nil {
					msg := fmt.Sprintf("Failed to get random IP from %v", m.cmdOpts.RandDest)
					panic(msg)
				}
			}
			if m.cmdOpts.RandSource != "" {
				v.SrcIP = getRandomIPv4(m.cmdOpts.RandSource)
				if v.SrcIP == nil {
					panic("Failed to get random IP")
				}
			}
			l := []gopacket.SerializableLayer{v}
			for _, p := range protoLayers {
				l = append(l, p.(gopacket.SerializableLayer))
			}
			l = append(l, gopacket.Payload(payload))
			if err := m.rawSockSend(l...); err != nil {
				// if err := m.rawSockSend(v, t.(gopacket.SerializableLayer), gopacket.Payload(payload)); err != nil {
				log.Errorf("error raw socket sending %v, %v: %v", v.NetworkFlow(), protoLayers, err)
			} else {
				m.streamFactory.OnSend(v, protoLayers, payload)
			}

		case *layers.IPv6:
			if m.cmdOpts.RandDest != "" {
				v.DstIP = getRandomIPv6(m.cmdOpts.RandDest)
				if v.DstIP == nil {
					panic("Failed to get random IP")
				}
			}
			if m.cmdOpts.RandSource != "" {
				v.SrcIP = getRandomIPv6(m.cmdOpts.RandSource)
				if v.SrcIP == nil {
					panic("Failed to get random IP")
				}
			}
			l := []gopacket.SerializableLayer{v}
			for _, p := range protoLayers {
				l = append(l, p.(gopacket.SerializableLayer))
			}
			l = append(l, gopacket.Payload(payload))

			if err := m.rawSockSend(l...); err != nil {
				log.Errorf("error raw socket sending %v, %v: %v", v.NetworkFlow(), protoLayers, err)
			} else {
				m.streamFactory.OnSend(v, protoLayers, payload)
			}

		default:
			return fmt.Errorf("cannot use layer type %v for checksum network layer", netLayer.LayerType())
		}

		sentPackets += 1
		if sentPackets == m.cmdOpts.Count {
			log.V(1).Infof("Sent %v packets, exiting in 1 second", sentPackets)
			time.Sleep(1 * time.Second)
			return nil
		}

		select {
		case <-time.After(m.cmdOpts.Interval):
			continue
		case <-m.ctx.Done():
			log.Warningf("Asked to terminiate early \n")
			return nil
		}
	}
}

func (m *packetStreamMgmr) StartStream() error {
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
	} else {
		ipv4 = layers.IPv4{
			SrcIP:    m.src,
			DstIP:    m.dst,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
	}

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go m.waitPackets(stop)
	defer close(stop)
	log.Infof("Start Streaming, time: %v", time.Now())
	if m.cmdOpts.IPv6 {
		m.sendPackets(&ipv6)
	} else {
		m.sendPackets(&ipv4)
	}

	log.Infof("Return from Stream, time: %v", time.Now())
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
