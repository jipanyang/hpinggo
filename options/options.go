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
	Interval      time.Duration // Interval between sending each packet.
	Count         uint          // Number of packets to generate, 0 is infinite.
	RandDest      bool          // Enables the random destination mode
	Delimiter     string        // Delimiter between path elements when converted to string.
	Display       func([]byte)  // Function called to display each result.
	DisplayPrefix string        // Prefix for each line of result output.
	DisplayIndent string        // Indent per nesting level of result output.
	DisplayPeer   bool          // Display the immediate connected peer.

	RawSocket bool // Use raw socket for sending packet when true

	Interface string // Packet outgoing interface
	// <empty string> - disable timestamp
	// on - human readable timestamp according to layout
	// raw - int64 nanos since epoch
	// <FORMAT> - human readable timestamp according to <FORMAT>
	Timestamp string // Formatting of timestamp in result output.
	Ipv6      bool   // run in ipv6 mode

	// port groups are comma separated: a number describes just a single port,
	// so 1,2,3 means port 1, 2 and 3. ranges are specified using a start-end notation,
	// like 1-1000, that is to scan ports between 1 and 1000 (included).
	// the special word all is an alias for 0-65535, while the special word known includes
	// all the ports listed in /etc/services. Groups can be combined, so the following command
	// line will scan ports between 1 and 1000 AND port 8888 AND ports listed in /etc/services
	Scan string // Ports range to scan

	// tcp options
	TcpTimestamp bool // Enable the TCP timestamp option, and try to guess the timestamp update frequency and the remote system uptime.
	fin          bool // Set FIN tcp flag
	syn          bool // Set SYN tcp flag
	rst          bool // Set RST tcp flag
	push         bool // Set PUSH tcp flag
	ack          bool // Set ACK tcp flag
	urg          bool // Set URG tcp flag
	xmas         bool // Set Xmas tcp flag
	ymas         bool // Set Ymas tcp flag
}

// TODO: display all parsed options
// Implementing Stringer interface
func (opt Options) String() string {
	return fmt.Sprintf("Interval %v", opt.Interval)
}
