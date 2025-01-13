// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package commands

import (
	"fmt"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	v3 "github.com/projectcalico/calico/felix/bpf/conntrack/v3"
	"github.com/projectcalico/calico/felix/bpf/maps"

	"github.com/docopt/docopt-go"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type conntrackDumpTCCmd struct {
	*cobra.Command
	Version    string `docopt:"--ver"`
	version    string
	MaxEntries int
	Debug      bool
}

func newConntrackDumpTCCmd() *cobra.Command {
	cmd := &conntrackDumpTCCmd{
		Command: &cobra.Command{
			Use:   "dumptc [--ver=<version>]",
			Short: "Dumps connection tracking table",
		},
	}
	cmd.Command.Flags().StringVarP((&cmd.version), "ver", "v", "", "version to dump from")
	cmd.Command.Flags().IntVarP((&cmd.MaxEntries), "mapsize", "m", v3.MaxEntries, "conntrack map size")
	cmd.Command.Flags().BoolVarP((&cmd.Debug), "debug", "d", false, "debug mode")
	cmd.Command.Args = cmd.Args
	cmd.Command.Run = cmd.Run

	return cmd.Command
}

func (cmd *conntrackDumpTCCmd) Args(c *cobra.Command, args []string) error {
	a, err := docopt.ParseArgs(makeDocUsage(c), args, "")
	if err != nil {
		return errors.New(err.Error())
	}
	err = a.Bind(cmd)
	if err != nil {
		return errors.New(err.Error())
	}
	return nil
}

func (cmd *conntrackDumpTCCmd) Run(c *cobra.Command, _ []string) {
	var ctMap maps.Map

	// Set the map size based on the actual max entries obtained from the map info.
	if err := cmd.setCTMapSize(); err != nil {
		log.WithError(err).Fatal("Failed to set ConntrackMap size")
	}

	ctMap = cmd.getCTMap()

	if err := ctMap.Open(); err != nil {
		if cmd.Debug {
			fmt.Printf("[debug] Failed to access ConntrackMap: err: %+v\n", err)
		}
		log.WithError(err).Fatal("Failed to access ConntrackMap")
	}
	if cmd.version == "2" {
		if cmd.Debug {
			fmt.Println("[debug] cmd.version == 2")
		}
		err := dumpCtMapV2(ctMap)
		if err != nil {
			if cmd.Debug {
				fmt.Printf("[debug] Failed to iterate over conntrack entries: err: %+v\n", err)
			}
			log.WithError(err).Fatal("Failed to iterate over conntrack entries")
		}
		return
	}

	keyFromBytes := conntrack.KeyFromBytes
	valFromBytes := conntrack.ValueFromBytes
	if ipv6 != nil && *ipv6 {
		keyFromBytes = conntrack.KeyV6FromBytes
		valFromBytes = conntrack.ValueV6FromBytes
	}

	var (
		totalConn int
		NatConn   int

		TCP    int
		UDP    int
		Others int

		TCPEstablished int
		TCPClosed      int
		TCPReset       int
		TCPSYNSent     int
	)

	fn := func(k conntrack.KeyInterface, v conntrack.ValueInterface) {
		if v.Type() == conntrack.TypeNATForward {
			NatConn++
			return
		}

		totalConn++

		if k.Proto() == conntrack.ProtoTCP {
			TCP++
		} else if k.Proto() == conntrack.ProtoUDP {
			UDP++
			return
		} else {
			Others++
			return
		}

		data := v.Data()

		if (v.IsForwardDSR() && data.FINsSeenDSR()) || data.FINsSeen() {
			TCPClosed++
			return
		}

		if data.RSTSeen() {
			TCPReset++
			return
		}

		if data.Established() {
			TCPEstablished++
			return
		}

		TCPSYNSent++
	}

	err := ctMap.Iter(func(k, v []byte) maps.IteratorAction {
		ctKey := keyFromBytes(k)
		ctVal := valFromBytes(v)

		fn(ctKey, ctVal)
		return maps.IterNone
	})

	cmd.Printf("Total connections: %d\n", totalConn+NatConn)
	cmd.Printf("Total entries: %d\n", totalConn+NatConn)
	cmd.Printf("NAT connections: %d\n\n", NatConn)
	cmd.Printf("TCP : %d\n", TCP)
	cmd.Printf("UDP : %d\n", UDP)
	cmd.Printf("Others : %d\n\n", Others)
	cmd.Printf("TCP Established: %d\n", TCPEstablished)
	cmd.Printf("TCP Closed: %d\n", TCPClosed)
	cmd.Printf("TCP Reset: %d\n", TCPReset)
	cmd.Printf("TCP Syn-sent: %d\n", TCPSYNSent)

	if err != nil {
		if cmd.Debug {
			fmt.Printf("[debug] Failed to iterate over conntrack entries: err: %+v\n", err)
		}
		log.WithError(err).Fatal("Failed to iterate over conntrack entries")
	}
}

func (cmd *conntrackDumpTCCmd) getCTMap() maps.Map {
	var ctMap maps.Map
	switch cmd.version {
	case "2":
		ctMap = conntrack.MapV2()
		if cmd.Debug {
			fmt.Printf("[debug] ctMap = conntrack.MapV2() \n")
		}
	default:
		if ipv6 != nil && *ipv6 {
			if cmd.Debug {
				fmt.Printf("[debug] ctMap = conntrack.MapV6() \n")
			}
			ctMap = conntrack.MapV6()
		} else {
			if cmd.Debug {
				fmt.Printf("[debug] ctMap = conntrack.Map() \n")
			}
			ctMap = conntrack.Map()
		}
	}
	return ctMap
}

func (cmd *conntrackDumpTCCmd) setCTMapSize() error {
	ctMap := cmd.getCTMap()

	if err := ctMap.Open(); err != nil {
		return errors.New("Failed to access ConntrackMap")
	}

	if mapInfo, err := maps.GetMapInfo(ctMap.MapFD()); err != nil {
		return errors.New("Failed to get map info")
	} else {
		// Set the map size based on the actual max entries obtained from the map info.
		maps.SetSize(ctMap.GetName(), mapInfo.MaxEntries)

		if cmd.Debug {
			fmt.Printf("[debug] map:%s, set size: %d\n", ctMap.GetName(), mapInfo.MaxEntries)
		}
	}

	if cmd.Debug {
		fmt.Printf("[debug] map:%s, get size: %d\n", ctMap.GetName(), maps.Size(ctMap.GetName()))
	}

	return nil
}
