package packetstream

import (
	"fmt"
	log "github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"os"
)

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
