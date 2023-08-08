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

package qrm

import (
	"fmt"
	"strings"
	"sync"

	"github.com/kubewharf/katalyst-core/cmd/katalyst-agent/app/agent"
	phconsts "github.com/kubewharf/katalyst-core/pkg/agent/utilcomponent/periodicalhandler/consts"
	"github.com/kubewharf/katalyst-core/pkg/config"
)

const (
	QRMPluginNameIO = "qrm_io_plugin"
)

var (
	QRMIOPluginPeriodicalHandlerGroupName = strings.Join([]string{QRMPluginNameIO,
		phconsts.PeriodicalHandlersGroupNameSuffix}, phconsts.GroupNameSeparator)
)

// ioPolicyInitializers is used to store the initializing function for io resource plugin policies
var ioPolicyInitializers sync.Map

// RegisterIOPolicyInitializer is used to register user-defined resource plugin init functions
func RegisterIOPolicyInitializer(name string, initFunc agent.InitFunc) {
	ioPolicyInitializers.Store(name, initFunc)
}

// getIOPolicyInitializers returns those policies with initialized functions
func getIOPolicyInitializers() map[string]agent.InitFunc {
	agents := make(map[string]agent.InitFunc)
	ioPolicyInitializers.Range(func(key, value interface{}) bool {
		agents[key.(string)] = value.(agent.InitFunc)
		return true
	})
	return agents
}

// InitQRMIOPlugins initializes the io QRM plugins
func InitQRMIOPlugins(agentCtx *agent.GenericContext, conf *config.Configuration, extraConf interface{}, agentName string) (bool, agent.Component, error) {
	initializers := getIOPolicyInitializers()
	policyName := conf.IOQRMPluginConfig.PolicyName

	initFunc, ok := initializers[policyName]
	if !ok {
		return false, agent.ComponentStub{}, fmt.Errorf("invalid policy name %v for io resource plugin", policyName)
	}

	return initFunc(agentCtx, conf, extraConf, agentName)
}
