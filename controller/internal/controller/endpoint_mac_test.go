/*
Copyright 2025.

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

package controller

import (
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("endpointMAC", func() {
	DescribeTable("derives a locally administered unicast MAC from an IPv4 address",
		func(input net.IP, want string, wantErr bool) {
			got, err := endpointMAC(input)
			if wantErr {
				Expect(err).To(HaveOccurred())
				Expect(got).To(BeEmpty())
				return
			}
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(want))
		},
		Entry("dotted IPv4", net.ParseIP("10.16.0.9"), "02:00:0a:10:00:09", false),
		Entry("4-byte IPv4", net.IPv4(192, 168, 255, 1).To4(), "02:00:c0:a8:ff:01", false),
		Entry("IPv4 zero address", net.ParseIP("0.0.0.0"), "02:00:00:00:00:00", false),
		Entry("IPv6", net.ParseIP("fd00::1"), "", true),
		Entry("nil", nil, "", true),
	)
})
