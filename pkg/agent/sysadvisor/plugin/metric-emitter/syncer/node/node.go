/*
Copyright 2022 The Katalyst Authors.

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

package node

import (
	"context"
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	apimetricnode "github.com/kubewharf/katalyst-api/pkg/metric/node"
	"github.com/kubewharf/katalyst-core/pkg/agent/sysadvisor/metacache"
	"github.com/kubewharf/katalyst-core/pkg/agent/sysadvisor/plugin/metric-emitter/syncer"
	"github.com/kubewharf/katalyst-core/pkg/agent/sysadvisor/plugin/metric-emitter/types"
	"github.com/kubewharf/katalyst-core/pkg/config"
	metricemitter "github.com/kubewharf/katalyst-core/pkg/config/agent/sysadvisor/metric-emitter"
	"github.com/kubewharf/katalyst-core/pkg/consts"
	"github.com/kubewharf/katalyst-core/pkg/custom-metric/store/data"
	"github.com/kubewharf/katalyst-core/pkg/metaserver"
	"github.com/kubewharf/katalyst-core/pkg/metaserver/agent/metric"
	"github.com/kubewharf/katalyst-core/pkg/metrics"
)

// nodeRawMetricNameMapping maps the raw metricName (collected from agent.MetricsFetcher)
// to the standard metricName (used by custom-metric-api-server)
var nodeRawMetricNameMapping = map[string]string{
	consts.MetricLoad1MinSystem:     apimetricnode.CustomMetricNodeCPULoad1Min,
	consts.MetricMemFreeSystem:      apimetricnode.CustomMetricNodeMemoryFree,
	consts.MetricMemAvailableSystem: apimetricnode.CustomMetricNodeMemoryAvailable,
}

// nodeCachedMetricNameMapping maps the cached metricName (processed by plugin.SysAdvisorPlugin)
// to the standard metricName (used by custom-metric-api-server)

type MetricSyncerNode struct {
	conf *metricemitter.MetricEmitterPluginConfiguration
	node *v1.Node

	metricEmitter metrics.MetricEmitter
	dataEmitter   metrics.MetricEmitter

	metaServer *metaserver.MetaServer
	metaReader metacache.MetaReader
}

func NewMetricSyncerNode(conf *config.Configuration, _ interface{}, metricEmitter, dataEmitter metrics.MetricEmitter,
	metaServer *metaserver.MetaServer, metaReader metacache.MetaReader) (syncer.CustomMetricSyncer, error) {
	return &MetricSyncerNode{
		conf: conf.AgentConfiguration.MetricEmitterPluginConfiguration,

		metricEmitter: metricEmitter,
		dataEmitter:   dataEmitter,
		metaServer:    metaServer,
		metaReader:    metaReader,
	}, nil
}

func (n *MetricSyncerNode) Name() string {
	return types.MetricSyncerNameNode
}

func (n *MetricSyncerNode) Run(ctx context.Context) {
	rChan := make(chan metric.NotifiedResponse, 20)

	// there is no need to deRegister for node-related metric
	for rawMetricName := range nodeRawMetricNameMapping {
		klog.Infof("register raw node metric: %v", rawMetricName)
		n.metaServer.MetricsFetcher.RegisterNotifier(metric.MetricsScopeNode, metric.NotifiedRequest{
			MetricName: rawMetricName,
		}, rChan)
	}

	go n.receiveRawNode(ctx, rChan)
}

// receiveRawNode receives notified response from raw data source
func (n *MetricSyncerNode) receiveRawNode(ctx context.Context, rChan chan metric.NotifiedResponse) {
	for {
		select {
		case response := <-rChan:
			if response.Req.MetricName == "" {
				continue
			}

			targetMetricName, ok := nodeRawMetricNameMapping[response.Req.MetricName]
			if !ok {
				klog.Warningf("invalid node raw metric name: %v", response.Req.MetricName)
				continue
			}

			klog.V(4).Infof("get metric %v for node", response.Req.MetricName)
			if tags := n.generateMetricTag(ctx); len(tags) > 0 {
				_ = n.dataEmitter.StoreFloat64(targetMetricName, response.Result, metrics.MetricTypeNameRaw, append(tags,
					metrics.MetricTag{
						Key: fmt.Sprintf("%s", data.CustomMetricLabelKeyTimestamp),
						Val: fmt.Sprintf("%v", response.Timestamp.UnixMilli()),
					})...)
			}
		case <-ctx.Done():
			klog.Infof("metric emitter for node has been stopped")
			return
		}
	}
}

// generateMetricTag generates tags that are bounded to current Node object
func (n *MetricSyncerNode) generateMetricTag(ctx context.Context) (tags []metrics.MetricTag) {
	if n.node == nil {
		node, err := n.metaServer.GetNode(ctx)
		if err != nil {
			klog.Warningf("get current node failed: %v", err)
			return
		}
		n.node = node
	}

	if n.node != nil {
		tags = []metrics.MetricTag{
			{
				Key: fmt.Sprintf("%s", data.CustomMetricLabelKeyObject),
				Val: "nodes",
			},
			{
				Key: fmt.Sprintf("%s", data.CustomMetricLabelKeyObjectName),
				Val: n.node.Name,
			},
		}
		for key, value := range n.node.Labels {
			if n.conf.NodeMetricLabel.Has(key) {
				tags = append(tags, metrics.MetricTag{
					Key: fmt.Sprintf("%s%s", data.CustomMetricLabelSelectorPrefixKey, key),
					Val: value,
				})
			}
		}
	}

	return tags
}
