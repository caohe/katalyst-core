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

package provider

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	"k8s.io/metrics/pkg/apis/custom_metrics"
	"k8s.io/metrics/pkg/apis/external_metrics"
	"sigs.k8s.io/custom-metrics-apiserver/pkg/provider"

	katalyst_base "github.com/kubewharf/katalyst-core/cmd/base"
	"github.com/kubewharf/katalyst-core/pkg/custom-metric/store"
	"github.com/kubewharf/katalyst-core/pkg/custom-metric/store/data"
	"github.com/kubewharf/katalyst-core/pkg/metrics"
)

const (
	metricsNameKCMASProviderReqCosts = "kcmas_provider_req_costs"
	metricsNameKCMASProviderReqCount = "kcmas_provider_req_count"

	metricsNameKCMASProviderDataCount = "kcmas_provider_data_count"
	metricsNameKCMASProviderDataEmpty = "kcmas_provider_data_empty"
)

// MetricProvider is a standard interface to query metric data;
// to simplify the implementation, MetricProvider use the standard kubernetes interface for
// custom-metrics and external-metrics; and provider.MetricsProvider may have different
// explanations for their parameters, we make the following appoints
//
// - GetMetricByName
// --- if metric name is nominated, ignore the selector;
// --- otherwise, return all the metrics matched with the metric selector;
// --- in all cases, we should check whether the objects (that own this metric) is matched (with name)
// --- only returns the latest value
//
// - GetMetricBySelector
// --- if metric name is nominated, ignore the selector;
// --- otherwise, return all the metrics matched with the metric selector;
// --- in all cases, we should check whether the objects (that own this metric) is matched (with label selector)
//
// - GetExternalMetric
// --- if metric name is nominated, ignore the metric selector;
// --- otherwise, return all the metrics matched with the metric selector;
//
type MetricProvider interface {
	provider.MetricsProvider
}

type MetricProviderImp struct {
	ctx            context.Context
	metricsEmitter metrics.MetricEmitter
	storeImp       store.MetricStore
}

func NewMetricProviderImp(ctx context.Context, baseCtx *katalyst_base.GenericContext, storeImp store.MetricStore) *MetricProviderImp {
	metricsEmitter := baseCtx.EmitterPool.GetDefaultMetricsEmitter()
	if metricsEmitter == nil {
		metricsEmitter = metrics.DummyMetrics{}
	}

	return &MetricProviderImp{
		ctx:            ctx,
		metricsEmitter: metricsEmitter,
		storeImp:       storeImp,
	}
}

func (m *MetricProviderImp) GetMetricByName(ctx context.Context, namespacedName types.NamespacedName,
	info provider.CustomMetricInfo, metricSelector labels.Selector) (*custom_metrics.MetricValue, error) {
	klog.Infof("GetMetricByName: metric name %v, object %v, namespace %v, object name %v, metricSelector %v",
		info.Metric, info.GroupResource, namespacedName.Namespace, namespacedName.Name, metricSelector)
	var (
		internalList []*data.InternalMetric
		err          error
		start        = time.Now()
	)
	defer func() {
		m.emitMetrics("GetMetricByName", info.Metric, namespacedName.Name, start, 1, err)
	}()

	internalList, err = m.storeImp.GetMetric(ctx, namespacedName.Namespace, info.Metric, namespacedName.Name,
		&info.GroupResource, nil, metricSelector, 1)
	if err != nil {
		klog.Errorf("GetMetric err: %v", err)
		return nil, err
	}

	var res *custom_metrics.MetricValue
	for _, internal := range internalList {
		if internal.GetObjectKind() == "" || internal.GetObjectName() == "" {
			klog.Errorf("custom metric %v doesn't have object %v/%v",
				internal.Name, internal.GetObjectKind(), internal.GetObjectName())
			continue
		}

		if res == nil {
			res = findMetricValueLatest(internal.Name, PackMetricValueList(internal))
		} else {
			res = findMetricValueLatest(internal.Name, append(PackMetricValueList(internal), *res))
		}
	}

	if res == nil {
		return nil, fmt.Errorf("no mtaching metric exists")
	}
	return res, nil
}

func (m *MetricProviderImp) GetMetricBySelector(ctx context.Context, namespace string, objSelector labels.Selector,
	info provider.CustomMetricInfo, metricSelector labels.Selector) (*custom_metrics.MetricValueList, error) {
	klog.Infof("GetMetricBySelector: metric name %v, object %v, namespace %v, objSelector %v, metricSelector %v",
		info.Metric, info.GroupResource, namespace, objSelector, metricSelector)
	var (
		internalList []*data.InternalMetric
		resultCount  int
		err          error
		start        = time.Now()
	)
	defer func() {
		m.emitMetrics("GetMetricBySelector", info.Metric, "", start, resultCount, err)
	}()

	internalList, err = m.storeImp.GetMetric(ctx, namespace, info.Metric, "",
		&info.GroupResource, objSelector, metricSelector, -1)
	if err != nil {
		klog.Errorf("GetMetric err: %v", err)
		return nil, err
	}

	var items []custom_metrics.MetricValue
	for _, internal := range internalList {
		if internal.GetObjectKind() == "" || internal.GetObjectName() == "" {
			klog.Errorf("custom metric %v doesn't have object %v/%v",
				internal.Name, internal.GetObjectKind(), internal.GetObjectName())
			continue
		}

		resultCount += internal.Len()
		items = append(items, PackMetricValueList(internal)...)
	}
	return &custom_metrics.MetricValueList{
		Items: items,
	}, nil
}

func (m *MetricProviderImp) ListAllMetrics() []provider.CustomMetricInfo {
	klog.V(6).Info("ListAllMetrics")
	var (
		metricTypeList []data.MetricMeta
		resultCount    int
		err            error
		start          = time.Now()
	)
	defer func() {
		m.emitMetrics("ListAllMetrics", "", "", start, resultCount, err)
	}()

	metricTypeList, err = m.storeImp.ListMetricMeta(context.Background(), true)
	if err != nil {
		klog.Errorf("ListAllMetrics err: %v", err)
		return []provider.CustomMetricInfo{}
	}

	infoMap := make(map[provider.CustomMetricInfo]interface{})
	for _, metricType := range metricTypeList {
		if metricType.GetObjectKind() == "" {
			continue
		}

		_, gr := schema.ParseResourceArg(metricType.GetObjectKind())
		infoMap[provider.CustomMetricInfo{
			GroupResource: gr,
			Namespaced:    metricType.GetNamespaced(),
			Metric:        metricType.GetName(),
		}] = struct{}{}
	}

	var res []provider.CustomMetricInfo
	for info := range infoMap {
		resultCount++
		res = append(res, info)
	}
	return res
}

func (m *MetricProviderImp) GetExternalMetric(ctx context.Context, namespace string, metricSelector labels.Selector,
	info provider.ExternalMetricInfo) (*external_metrics.ExternalMetricValueList, error) {
	klog.Infof("GetExternalMetric: metric name %v, namespace %v, metricSelector %v", info.Metric, namespace, metricSelector)
	var (
		internalList []*data.InternalMetric
		resultCount  int
		err          error
		start        = time.Now()
	)
	defer func() {
		m.emitMetrics("GetExternalMetric", info.Metric, "", start, resultCount, err)
	}()

	internalList, err = m.storeImp.GetMetric(ctx, namespace, info.Metric, "", nil, nil, metricSelector, -1)
	if err != nil {
		klog.Errorf("GetMetric err: %v", err)
		return nil, err
	}

	var items []external_metrics.ExternalMetricValue
	for _, internal := range internalList {
		if internal.GetObjectKind() != "" || internal.GetObjectName() != "" {
			klog.Errorf("internal metric %v has object %v/%v unexpectedly",
				internal.Name, internal.GetObjectKind(), internal.GetObjectName())
			continue
		}

		resultCount += internal.Len()
		items = append(items, PackExternalMetricValueList(internal)...)
	}
	return &external_metrics.ExternalMetricValueList{
		Items: items,
	}, nil
}

func (m *MetricProviderImp) ListAllExternalMetrics() []provider.ExternalMetricInfo {
	klog.V(6).Info("ListAllExternalMetrics")
	var (
		internalList []data.MetricMeta
		resultCount  int
		err          error
		start        = time.Now()
	)
	defer func() {
		m.emitMetrics("ListAllExternalMetrics", "", "", start, resultCount, err)
	}()

	internalList, err = m.storeImp.ListMetricMeta(context.Background(), false)
	if err != nil {
		klog.Errorf("ListAllExternalMetrics err: %v", err)
		return []provider.ExternalMetricInfo{}
	}

	infoMap := make(map[provider.ExternalMetricInfo]interface{})
	for _, internal := range internalList {
		if internal.GetObjectKind() != "" {
			continue
		}

		infoMap[provider.ExternalMetricInfo{
			Metric: internal.GetName(),
		}] = struct{}{}
	}

	var res []provider.ExternalMetricInfo
	for info := range infoMap {
		resultCount++
		res = append(res, info)
	}
	return res
}

// emitMetrics provides a unified way to emit metrics about the running states for each interface.
func (m *MetricProviderImp) emitMetrics(function string, metricName, objName string, reqStart time.Time, resultCount int, err error) {
	now := time.Now()
	var (
		reqCosts = now.Sub(reqStart).Microseconds()
		success  = err == nil
	)
	klog.V(3).Infof("[provider] function [%v]: costs %v(ms), resultCount %v, success: %v", function, reqCosts, resultCount, success)

	if metricName == "" {
		metricName = "empty"
	}
	if objName == "" {
		objName = "empty"
	}
	tags := []metrics.MetricTag{
		{Key: "function", Val: fmt.Sprintf("%v", function)},
		{Key: "metric_name", Val: metricName},
		{Key: "object_name", Val: objName},
	}

	_ = m.metricsEmitter.StoreInt64(metricsNameKCMASProviderReqCosts, reqCosts, metrics.MetricTypeNameRaw, append(tags,
		metrics.MetricTag{Key: "success", Val: fmt.Sprintf("%v", success)})...)
	_ = m.metricsEmitter.StoreInt64(metricsNameKCMASProviderReqCount, 1, metrics.MetricTypeNameCount, append(tags,
		metrics.MetricTag{Key: "success", Val: fmt.Sprintf("%v", success)})...)

	if success {
		_ = m.metricsEmitter.StoreInt64(metricsNameKCMASProviderDataCount, int64(resultCount), metrics.MetricTypeNameRaw, tags...)
		if resultCount == 0 {
			_ = m.metricsEmitter.StoreInt64(metricsNameKCMASProviderDataEmpty, 1, metrics.MetricTypeNameCount, tags...)
		}
	}
}
