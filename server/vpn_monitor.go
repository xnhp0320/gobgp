// Copyright (C) 2015-2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
)

type VpnRouteMsgHeader struct {
	Length uint32
}

const (
	VPN_ROUTE_MSG_HEADER_SIZE = 4
)

func (hdr *VpnRouteMsgHeader) DecodeFromBytes(data []byte) {
	hdr.Length = binary.BigEndian.Uint32(data[0:4])
}

func (hdr *VpnRouteMsgHeader) Serialize() ([]byte, error) {
	buf := make([]byte, VPN_ROUTE_MSG_HEADER_SIZE)
	binary.BigEndian.PutUint32(buf[0:4], hdr.Length)
	return buf, nil
}

type VpnRouteMsg struct {
	RD      string
	Nexthop string
	Prefix  string
	Length  uint8
	Isdraw  bool
}

func SplitVpnRouteMsg(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 || len(data) < VPN_ROUTE_MSG_HEADER_SIZE {
		return 0, nil, nil
	}

	hdr := &VpnRouteMsgHeader{}
	hdr.DecodeFromBytes(data)
	if uint32(len(data)) < hdr.Length {
		return 0, nil, nil
	}

	return int(hdr.Length), data[0:hdr.Length], nil
}

func (b *vpnMonClient) tryConnect() *net.TCPConn {
	interval := 1
	for {
		log.WithFields(log.Fields{"Topic": "vpn_monitor"}).Debugf("Connecting vpnMon server:%s", b.host)
		conn, err := net.Dial("tcp", b.host)
		if err != nil {
			select {
			case <-b.dead:
				return nil
			default:
			}
			time.Sleep(time.Duration(interval) * time.Second)
			if interval < 30 {
				interval *= 2
			}
		} else {
			log.WithFields(log.Fields{"Topic": "vpn_monitor"}).Infof("vpnMon server is connected:%s", b.host)
			return conn.(*net.TCPConn)
		}
	}
}

func (b *vpnMonClient) Stop() {
	close(b.dead)
}

func (b *vpnMonClient) loop() {
	for {
		conn := b.tryConnect()
		if conn == nil {
			break
		}

		if func() bool {
			ops := []WatchOption{WatchUpdate(true)}
			w := b.s.Watch(ops...)
			defer w.Stop()

			write := func(msgs []VpnRouteMsg) error {
				var hdr VpnRouteMsgHeader
				jsonbuf, err := json.Marshal(msgs)
				if err != nil {
					log.Warn("failed to marshal VpnRouteMsg")
					return err
				}

				hdr.Length = uint32(len(jsonbuf))
				buf, _ := hdr.Serialize()
				buf = append(buf, jsonbuf...)

				_, err = conn.Write(buf)
				if err != nil {
					log.Warnf("failed to write to bmp server %s", b.host)
				}
				return err
			}

			handle := func(pathList []*table.Path) ([]VpnRouteMsg, bool) {
				vpnmsgs := []VpnRouteMsg{}
				push := false
				for _, p := range pathList {
					attrs := p.GetPathAttrs()
					for _, attr := range attrs {
						if attr.GetType() == bgp.BGP_ATTR_TYPE_MP_REACH_NLRI {
							push = true
							MpReachNLRI := attr.(*bgp.PathAttributeMpReachNLRI)
							for _, addrprefix := range MpReachNLRI.Value {
								labledAddrprefix := addrprefix.(*bgp.LabeledVPNIPAddrPrefix)
								diff := uint8(8 * (labledAddrprefix.Labels.Len() + labledAddrprefix.RD.Len()))
								msg := VpnRouteMsg{
									RD:      labledAddrprefix.RD.String(),
									Nexthop: MpReachNLRI.Nexthop.String(),
									Prefix:  labledAddrprefix.Prefix.String(),
									Length:  labledAddrprefix.IPAddrPrefixDefault.Length - diff,
									Isdraw:  false,
								}
								vpnmsgs = append(vpnmsgs, msg)
							}
						} else if attr.GetType() == bgp.BGP_ATTR_TYPE_MP_UNREACH_NLRI {
							push = true
							MpReachNLRI := attr.(*bgp.PathAttributeMpReachNLRI)
							for _, addrprefix := range MpReachNLRI.Value {
								labledAddrprefix := addrprefix.(*bgp.LabeledVPNIPAddrPrefix)
								diff := uint8(8 * (labledAddrprefix.Labels.Len() + labledAddrprefix.RD.Len()))
								msg := VpnRouteMsg{
									RD:      labledAddrprefix.RD.String(),
									Nexthop: MpReachNLRI.Nexthop.String(),
									Prefix:  labledAddrprefix.Prefix.String(),
									Length:  labledAddrprefix.IPAddrPrefixDefault.Length - diff,
									Isdraw:  true,
								}
								vpnmsgs = append(vpnmsgs, msg)
							}
						}
					}
				}
				return vpnmsgs, push
			}

			for {
				select {
				case ev := <-w.Event():
					switch msg := ev.(type) {
					case *WatchEventUpdate:
						pathList := make([]*table.Path, 0, len(msg.PathList))
						for _, p := range msg.PathList {
							if b.ribout.update(p) {
								pathList = append(pathList, p)
							}
						}
						vpnmsg, push := handle(pathList)
						if push {
							write(vpnmsg)
						}
						return false
					case *WatchEventPeerState:
						return false
					}
				case <-b.dead:
					conn.Close()
					return true
				}
			}
		}() {
			return
		}
	}
}

type vpnMonClient struct {
	s      *BgpServer
	dead   chan struct{}
	host   string
	ribout ribout
}

type vpnMonManager struct {
	s         *BgpServer
	clientMap map[string]*vpnMonClient
}

func (b *vpnMonManager) addServer(c *config.VPNMonServerConfig) error {
	host := net.JoinHostPort(c.Address, strconv.Itoa(int(c.Port)))
	if _, y := b.clientMap[host]; y {
		return fmt.Errorf("vpnMon client %s is already configured", host)
	}
	b.clientMap[host] = &vpnMonClient{
		s:      b.s,
		dead:   make(chan struct{}),
		host:   host,
		ribout: newribout(),
	}
	go b.clientMap[host].loop()
	return nil
}

func (b *vpnMonManager) deleteServer(c *config.VPNMonServerConfig) error {
	host := net.JoinHostPort(c.Address, strconv.Itoa(int(c.Port)))
	h, ok := b.clientMap[host]
	if !ok {
		return fmt.Errorf("vpnMon client %s isn't found", host)
	}

	h.Stop()
	delete(b.clientMap, host)
	return nil
}

func newvpnMonClientManager(s *BgpServer) *vpnMonManager {
	return &vpnMonManager{
		s:         s,
		clientMap: make(map[string]*vpnMonClient),
	}
}
