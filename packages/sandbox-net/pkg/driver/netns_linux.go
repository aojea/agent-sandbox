// Copyright 2026 The Kubernetes Authors.
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

//go:build linux

package driver

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"

	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/socketat"
)

type linuxNetNSManager struct{}

// NewLinuxNetNSManager returns a NetNSManager backed by socketat and Linux netlink.
func NewLinuxNetNSManager() NetNSManager {
	return linuxNetNSManager{}
}

func (linuxNetNSManager) VerifyLoopbackOnly(netnsPath string) error {
	return socketat.DoAtNSPath(netnsPath, func() error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("open netlink handle in pod netns: %w", err)
		}
		defer handle.Close()

		links, err := handle.LinkList()
		if err != nil {
			return fmt.Errorf("list links in pod netns: %w", err)
		}
		for _, link := range links {
			if link.Attrs().Flags&net.FlagLoopback != 0 {
				continue
			}
			return fmt.Errorf("non-loopback network interface %q present in PodNetworkIsolated netns", link.Attrs().Name)
		}
		return nil
	})
}

func (linuxNetNSManager) FlushNonLoopbackRoutes(netnsPath string) error {
	return socketat.DoAtNSPath(netnsPath, func() error {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("open netlink handle in pod netns: %w", err)
		}
		defer handle.Close()

		links, err := handle.LinkList()
		if err != nil {
			return fmt.Errorf("list links in pod netns: %w", err)
		}
		for _, link := range links {
			if link.Attrs().Flags&net.FlagLoopback != 0 {
				continue
			}
			for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
				routes, err := handle.RouteList(link, family)
				if err != nil {
					return fmt.Errorf("list routes on %q: %w", link.Attrs().Name, err)
				}
				for i := range routes {
					if err := handle.RouteDel(&routes[i]); err != nil {
						return fmt.Errorf("delete route %v on %q: %w", routes[i], link.Attrs().Name, err)
					}
				}
			}
		}
		return nil
	})
}

func (linuxNetNSManager) ListenAt(netnsPath, network, address string) (net.Listener, error) {
	return socketat.ListenAtPath(netnsPath, network, address)
}
