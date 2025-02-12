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

// Package metaserver is the package that contains those implementations to
// obtain metadata in the specific node, any other component wants to get
// those data should import this package rather than get directly.
package metaserver // import "github.com/kubewharf/katalyst-core/pkg/metaserver"

import (
	"context"
	"fmt"
	"os"

	"github.com/kubewharf/katalyst-core/pkg/client"
	pkgconfig "github.com/kubewharf/katalyst-core/pkg/config"
	"github.com/kubewharf/katalyst-core/pkg/metaserver/agent"
	"github.com/kubewharf/katalyst-core/pkg/metaserver/config"
	"github.com/kubewharf/katalyst-core/pkg/metaserver/external"
	"github.com/kubewharf/katalyst-core/pkg/metaserver/spd"
	"github.com/kubewharf/katalyst-core/pkg/metrics"
)

// MetaServer is used to fetch metadata that other components may need to obtain,
// such as. dynamic configurations, pods or nodes running in agent, metrics info and so on.
type MetaServer struct {
	*agent.MetaAgent
	config.ConfigurationManager
	spd.ServiceProfileManager
	external.ExternalManager
}

// NewMetaServer returns the instance of MetaServer.
func NewMetaServer(clientSet *client.GenericClientSet, emitter metrics.MetricEmitter, conf *pkgconfig.Configuration) (*MetaServer, error) {
	metaAgent, err := agent.NewMetaAgent(conf, clientSet, emitter)
	if err != nil {
		return nil, err
	}

	// make sure meta server checkpoint directory already exist
	err = os.MkdirAll(conf.CheckpointManagerDir, os.FileMode(0755))
	if err != nil {
		return nil, fmt.Errorf("initializes meta server checkpoint dir failed: %s", err)
	}

	configurationManager, err := config.NewDynamicConfigManager(clientSet, emitter,
		metaAgent.CNCFetcher, conf)
	if err != nil {
		return nil, err
	}

	serviceProfileManager, err := spd.NewSPDManager(clientSet, emitter, metaAgent.CNCFetcher, conf)
	if err != nil {
		return nil, err
	}

	return &MetaServer{
		MetaAgent:             metaAgent,
		ConfigurationManager:  configurationManager,
		ServiceProfileManager: serviceProfileManager,
		ExternalManager:       external.InitExternalManager(metaAgent.PodFetcher),
	}, nil
}

func (m *MetaServer) Run(ctx context.Context) {
	go m.MetaAgent.Run(ctx)
	go m.ConfigurationManager.Run(ctx)
	go m.ServiceProfileManager.Run(ctx)
	go m.ExternalManager.Run(ctx)

	<-ctx.Done()
}
