package scanner

import (
	"context"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// packetConnSender handles packet to be sent on raw socket interface
// One usage example:
// sudo /usr/local/go/bin/go run cmd/hpinggo.go -target www.yahoo.com  -scan '80,443' -i 1ms -S -logtostderr=false
type packetConnSender struct {
	ctx context.Context

	// iface is the interface to send packets on.
	iface *net.Interface
	// destination, gateway (if applicable), and source IP addresses to use.
	dst, gw, src net.IP

	ethType layers.EthernetType

	// opts and buf allow us to easily serialize packets in the send()
	// method.
	packetOpts gopacket.SerializeOptions
	buf        gopacket.SerializeBuffer

	ipConn net.PacketConn
}

// NewPacketConnSender creates a new Sender based on the input info,
// it will use PacketConn interface for the sending .
func NewPacketConnSender(ctxParent context.Context, dst net.IP, gw net.IP, src net.IP,
	iface *net.Interface) (*packetConnSender, error) {

	p := &packetConnSender{
		ctx:   ctxParent,
		dst:   dst,
		gw:    gw,
		src:   src,
		iface: iface,
		packetOpts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}

	tmpIp := dst
	if tmpIp = tmpIp.To4(); tmpIp != nil {
		p.ethType = layers.EthernetTypeIPv4
	} else if dst = dst.To16(); dst != nil {
		p.ethType = layers.EthernetTypeIPv6
	} else {
		return nil, fmt.Errorf("Invalid dst IP: %v", dst)
	}
	var ipConn net.PacketConn
	var err error

	// TODO: use cases beyond tcp?
	if p.ethType == layers.EthernetTypeIPv6 {
		ipConn, err = net.ListenPacket("ip6:tcp", "::")
	} else {
		ipConn, err = net.ListenPacket("ip4:tcp", "0.0.0.0")
	}

	if err != nil {
		panic(err)
	}
	p.ipConn = ipConn
	return p, nil
}

func (p *packetConnSender) close() {

}

// packetConnSender sends the given layers as a single packet on the network.
func (p *packetConnSender) send(ls []gopacket.Layer, payload []byte) error {

	// Assuming just one layer for now.
	// TODO: use cases beyond tcp?
	transportLayer := ls[0]
	tcp := transportLayer.(*layers.TCP)

	if p.ethType == layers.EthernetTypeIPv6 {
		ipv6 := layers.IPv6{
			SrcIP:      p.src,
			DstIP:      p.dst,
			Version:    6,
			HopLimit:   255,
			NextHeader: layers.IPProtocolTCP,
		}
		tcp.SetNetworkLayerForChecksum(&ipv6)

	} else {
		ipv4 := layers.IPv4{
			SrcIP:    p.src,
			DstIP:    p.dst,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		tcp.SetNetworkLayerForChecksum(&ipv4)
	}

	if err := gopacket.SerializeLayers(p.buf, p.packetOpts, tcp, gopacket.Payload(payload)); err != nil {
		return err
	}

	dstIPaddr := net.IPAddr{
		IP: p.dst,
	}

	packetData := p.buf.Bytes()

	_, err := p.ipConn.WriteTo(packetData, &dstIPaddr)
	if err != nil {
		return err
	}
	return nil
}
