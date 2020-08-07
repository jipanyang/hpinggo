package scanner

import (
	"context"
	"fmt"
	log "github.com/golang/glog"
	"net"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// rawSocketSender handles packet to be sent on raw socket interface
// One usage example:
// sudo /usr/local/go/bin/go run cmd/hpinggo.go -target www.yahoo.com  -scan '80,443' -i 1ms -S -logtostderr=false
type rawSocketSender struct {
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

	socketFd int // fd of raw socket
}

// newRawSocketSender creates a new Sender based on the input info,
// it will use raw socket interface for the sending .
func newRawSocketSender(ctxParent context.Context, dst net.IP, gw net.IP, src net.IP,
	iface *net.Interface, fd int) (*rawSocketSender, error) {

	r := &rawSocketSender{
		ctx:      ctxParent,
		dst:      dst,
		gw:       gw,
		src:      src,
		iface:    iface,
		socketFd: fd,
		packetOpts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}

	tmpIp := dst
	if tmpIp = tmpIp.To4(); tmpIp != nil {
		r.ethType = layers.EthernetTypeIPv4
	} else if dst = dst.To16(); dst != nil {
		r.ethType = layers.EthernetTypeIPv6
	} else {
		return nil, fmt.Errorf("Invalid dst IP: %v", dst)
	}

	return r, nil
}

func (r *rawSocketSender) close() {

}

// raw socket sends the given layers as a single packet on the network.
func (r *rawSocketSender) send(ls []gopacket.Layer, payload []byte) error {

	// Assuming just one layer for now.
	// TODO: use cases beyond tcp?
	transportLayer := ls[0]
	tcp := transportLayer.(*layers.TCP)

	if r.ethType == layers.EthernetTypeIPv6 {
		ipv6 := layers.IPv6{
			SrcIP:      r.src,
			DstIP:      r.dst,
			Version:    6,
			HopLimit:   255,
			NextHeader: layers.IPProtocolTCP,
		}
		tcp.SetNetworkLayerForChecksum(&ipv6)
		if err := gopacket.SerializeLayers(r.buf, r.packetOpts, &ipv6, tcp, gopacket.Payload(payload)); err != nil {
			return err
		}
	} else {
		ipv4 := layers.IPv4{
			SrcIP:    r.src,
			DstIP:    r.dst,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		tcp.SetNetworkLayerForChecksum(&ipv4)
		if err := gopacket.SerializeLayers(r.buf, r.packetOpts, &ipv4, tcp, gopacket.Payload(payload)); err != nil {
			return err
		}
	}

	packetData := r.buf.Bytes()

	ip := []byte(r.dst)

	if r.ethType != layers.EthernetTypeIPv6 {

		var dstIp [4]byte
		copy(dstIp[:], ip[:4])

		addr := syscall.SockaddrInet4{
			Port: 0,
			Addr: dstIp,
		}
		err := syscall.Sendto(r.socketFd, packetData, 0, &addr)
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
		err := syscall.Sendto(r.socketFd, packetData, 0, &addr)
		if err != nil {
			log.Fatal("Sendto:", err)
		}
	}
	return nil
}
