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
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	juneauv1alpha1 "github.com/1outres/juneau/controller/api/v1alpha1"
)

const addressPoolCollectScrapeTimeout = 10 * time.Second

var addressPoolAddressesDesc = prometheus.NewDesc(
	"juneau_addresspool_addresses",
	"Number of addresses of an AddressPool by state: total, allocated or available.",
	[]string{"pool", "state"}, nil,
)

// AddressPoolCollector exposes the address counts that the AddressPool
// reconciler writes to status. It reads at scrape time, so the series of a
// deleted AddressPool disappear on their own.
type AddressPoolCollector struct {
	reader client.Reader
}

// NewAddressPoolCollector returns a collector that lists AddressPools from
// reader, usually the manager cache.
func NewAddressPoolCollector(reader client.Reader) *AddressPoolCollector {
	return &AddressPoolCollector{reader: reader}
}

// Describe implements prometheus.Collector.
func (c *AddressPoolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- addressPoolAddressesDesc
}

// Collect implements prometheus.Collector. A pool whose counts were not
// computed yet is skipped instead of reported as zero.
func (c *AddressPoolCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), addressPoolCollectScrapeTimeout)
	defer cancel()

	var pools juneauv1alpha1.AddressPoolList
	if err := c.reader.List(ctx, &pools); err != nil {
		ch <- prometheus.NewInvalidMetric(addressPoolAddressesDesc, err)
		log.FromContext(ctx).Error(err, "unable to list AddressPools for metrics")
		return
	}
	for _, pool := range pools.Items {
		if pool.Status.ObservedGeneration == 0 {
			continue
		}
		for state, value := range map[string]int64{
			"total":     pool.Status.TotalAddresses,
			"allocated": pool.Status.AllocatedAddresses,
			"available": pool.Status.AvailableAddresses,
		} {
			ch <- prometheus.MustNewConstMetric(addressPoolAddressesDesc, prometheus.GaugeValue, float64(value), pool.Name, state)
		}
	}
}
