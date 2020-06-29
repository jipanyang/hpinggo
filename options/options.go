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
	"time"
)

// Options is a type to hold parameters that affect how hpinggo generate and analyze packets
type Options struct {
	PollingInterval   time.Duration // Duration between polling events.
	StreamingDuration time.Duration // Duration to collect response, 0 is forever.
	Count             uint          // Number of packets to generate, 0 is infinite.
	RandDest          bool          // Enables the random destination mode
	Delimiter         string        // Delimiter between path elements when converted to string.
	Display           func([]byte)  // Function called to display each result.
	DisplayPrefix     string        // Prefix for each line of result output.
	DisplayIndent     string        // Indent per nesting level of result output.
	DisplayPeer       bool          // Display the immediate connected peer.
	Scan              string        // Ports range to scan
	RawSocket         bool          // Use raw socket for sending packet when true

	Interface string // Packet outgoing interface
	// <empty string> - disable timestamp
	// on - human readable timestamp according to layout
	// raw - int64 nanos since epoch
	// <FORMAT> - human readable timestamp according to <FORMAT>
	Timestamp string // Formatting of timestamp in result output.
	Ipv6      bool   // run in ipv6 mode
	Verbose   bool   // verbose pring
	Debug     bool   // debugging mode
}
