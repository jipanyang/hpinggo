/*
Copyright 2020 Jipan Yang
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package option provides options for hpinggo tool
package options

import (
	"fmt"
	"time"
)

// Options is a type to hold parameters that affect how hpinggo generate and analyze packets
type Options struct {
	Interval time.Duration // Interval between sending each packet.
	Count    int           // Number of packets to generate, 0 is infinite.
	// If specified (in format like x.x.x.x, 192,168.x.x, 128.x.x.255),
	// enables the random destination mode
	RandDest   string
	RandSource string // Enables the random source mode
	Data       int    // data size

	Delimiter     string // Delimiter between path elements when converted to string.
	DisplayPrefix string // Prefix for each line of result output.
	DisplayIndent string // Indent per nesting level of result output.
	DisplayPeer   bool   // Display the immediate connected peer.

	RawSocket bool // Use raw socket for sending packet when true

	Interface string // Packet outgoing interface
	// <empty string> - disable timestamp
	// on - human readable timestamp according to layout
	// raw - int64 nanos since epoch
	// <FORMAT> - human readable timestamp according to <FORMAT>
	Timestamp string // Formatting of timestamp in result output.
	IPv6      bool   // run in ipv6 mode

	// RAW IP mode, in this mode it will send IP header with data appended with
	// --signature and/or --file, see also --ipproto that allows you to set the ip protocol field.
	RawIp bool
	// ICMP mode, by default it will send ICMP echo-request,
	// you can set other ICMP type/code using --icmptype --icmpcode options.
	Icmp bool
	// UDP mode, by default it will send udp to target host's port 0.
	// UDP header tunable options are the following: --baseport, --destport, --keep.
	Udp bool

	// port groups are comma separated: a number describes just a single port,
	// so 1,2,3 means port 1, 2 and 3. ranges are specified using a start-end notation,
	// like 1-1000, that is to scan ports between 1 and 1000 (included).
	// the special word all is an alias for 0-65535, while the special word known includes
	// all the ports listed in /etc/services. Groups can be combined, so the following command
	// line will scan ports between 1 and 1000 AND port 8888 AND ports listed in /etc/services
	Scan string // Ports range to scan

	// tcp options, https://en.wikipedia.org/wiki/Transmission_Control_Protocol
	TcpTimestamp bool // Enable the TCP timestamp option, and try to guess the timestamp update frequency and the remote system uptime.
	// 	Flags (9 bits)
	// Contains 9 1-bit flags (control bits) as follows:
	// NS (1 bit): ECN-nonce - concealment protection[a]
	// CWR (1 bit): Congestion window reduced (CWR) flag is set by the sending host to indicate that it received a TCP segment with the ECE flag set and had responded in congestion control mechanism.[b]
	// ECE (1 bit): ECN-Echo has a dual role, depending on the value of the SYN flag. It indicates:
	// If the SYN flag is set (1), that the TCP peer is ECN capable.
	// If the SYN flag is clear (0), that a packet with Congestion Experienced flag set (ECN=11) in the IP header was received during normal transmission.[b] This serves as an indication of network congestion (or impending congestion) to the TCP sender.
	// URG (1 bit): Indicates that the Urgent pointer field is significant
	// ACK (1 bit): Indicates that the Acknowledgment field is significant. All packets after the initial SYN packet sent by the client should have this flag set.
	// PSH (1 bit): Push function. Asks to push the buffered data to the receiving application.
	// RST (1 bit): Reset the connection
	// SYN (1 bit): Synchronize sequence numbers. Only the first packet sent from each end should have this flag set. Some other flags and fields change meaning based on this flag, and some are only valid when it is set, and others when it is clear.
	// FIN (1 bit): Last packet from sender
	TcpFin  bool // Set FIN tcp flag
	TcpSyn  bool // Set SYN tcp flag
	TcpRst  bool // Set RST tcp flag
	TcpPush bool // Set PSH tcp flag
	TcpAck  bool // Set ACK tcp flag
	TcpUrg  bool // Set URG tcp flag
	TcpEce  bool // Set ECE tcp flag
	TcpCwr  bool // Set CWR tcp flag,
	TcpNs   bool // Set NS flag

	BaseSourcePort      int  // Initial source port number
	KeepConstSourcePort bool //keep still source port, see BaseSourcePort for more information.
	// [+][+]dest port Set destination port, default is 0. If '+' character precedes dest port number (i.e. +1024)
	// destination port will be increased for each reply received.
	// If double '+' precedes dest port number (i.e. ++1024), destination port will be increased for each packet sent.
	DestPort string // Set destination port
}

// TODO: display all parsed options
// Implementing Stringer interface
func (opt Options) String() string {
	var tcpFlags string
	if opt.TcpFin {
		tcpFlags += "FIN,"
	}
	if opt.TcpSyn {
		tcpFlags += "SYN,"
	}
	if opt.TcpRst {
		tcpFlags += "RST,"
	}
	if opt.TcpPush {
		tcpFlags += "PSH,"
	}
	if opt.TcpAck {
		tcpFlags += "ACK,"
	}
	if opt.TcpUrg {
		tcpFlags += "URG,"
	}
	if opt.TcpEce {
		tcpFlags += "ECE,"
	}
	if opt.TcpCwr {
		tcpFlags += "CWR,"
	}
	if opt.TcpNs {
		tcpFlags += "NS,"
	}
	if tcpFlags != "" {
		tcpFlags = tcpFlags[:len(tcpFlags)-1]
	}
	return fmt.Sprintf("Interval: %v, Interface: %v, IPv6: %v, TcpFlags: %v, "+
		"BaseSourcePort: %v, KeepConstSourcePort: %v, DestPort: %v, Data: %v "+
		"RandDest: %v, RandSource: %v",
		opt.Interval, opt.Interface, opt.IPv6, tcpFlags, opt.BaseSourcePort,
		opt.KeepConstSourcePort, opt.DestPort, opt.Data, opt.RandDest, opt.RandSource)
}
