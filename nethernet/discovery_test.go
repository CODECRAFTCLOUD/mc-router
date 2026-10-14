package nethernet

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	core "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const b1Namespace = "game"

func b1Service(name string, ann map[string]string, ports ...core.ServicePort) *core.Service {
	return &core.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: b1Namespace, Annotations: ann},
		Spec:       core.ServiceSpec{ClusterIP: "10.96.1.7", Ports: ports},
	}
}

func b1NNPort() core.ServicePort {
	return core.ServicePort{Name: "nethernet", Protocol: core.ProtocolTCP, Port: 19132}
}

func b1Published() map[string]string {
	return map[string]string{
		"nethernet.uniz.host/serverName": "survival.uniz.host,play.example.com",
		"nethernet.uniz.host/legacyPort": "30017",
		"nethernet.uniz.host/asleepMotd": "Sleeping - join to wake",
		"nethernet.uniz.host/serverId":   "65f0c0ffee",
	}
}

func b1Watch(t *testing.T, objs ...*core.Service) (*fake.Clientset, *RouteTable) {
	t.Helper()
	client := fake.NewClientset()
	for _, o := range objs {
		_, err := client.CoreV1().Services(b1Namespace).Create(context.Background(), o, metav1.CreateOptions{})
		require.NoError(t, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rt := NewRouteTable()
	require.NoError(t, WatchServices(ctx, client, b1Namespace, rt))
	return client, rt
}

func b1Eventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	require.Eventually(t, cond, 3*time.Second, 10*time.Millisecond, msg)
}

func TestDiscoveryRoutesAnnotatedService(t *testing.T) {
	_, rt := b1Watch(t, b1Service("mc-65f0c0ffee", b1Published(),
		core.ServicePort{Name: "minecraft", Port: 25565}, b1NNPort()))

	b, ok := rt.ByHost("survival.uniz.host")
	require.True(t, ok, "routes are loaded once WatchServices returns")
	assert.Equal(t, Backend{
		ServerID:   "65f0c0ffee",
		Addr:       netip.MustParseAddrPort("10.96.1.7:19132"),
		LegacyPort: 30017,
		AsleepMOTD: "Sleeping - join to wake",
	}, b)
	_, ok = rt.ByHost("play.example.com")
	assert.True(t, ok, "every comma-separated hostname routes")
	b, ok = rt.ByLegacyPort(30017)
	require.True(t, ok)
	assert.Equal(t, "65f0c0ffee", b.ServerID)
}

func TestDiscoveryRoutesAServiceAddedLater(t *testing.T) {
	client, rt := b1Watch(t)
	_, err := client.CoreV1().Services(b1Namespace).Create(context.Background(),
		b1Service("mc-x", b1Published(), b1NNPort()), metav1.CreateOptions{})
	require.NoError(t, err)
	b1Eventually(t, func() bool { _, ok := rt.ByHost("survival.uniz.host"); return ok }, "added Service routes")

	require.NoError(t, client.CoreV1().Services(b1Namespace).Delete(context.Background(), "mc-x", metav1.DeleteOptions{}))
	b1Eventually(t, func() bool { _, ok := rt.ByHost("survival.uniz.host"); return !ok }, "deleted Service unroutes")
}

func TestDiscoveryIgnoresJavaOnlyService(t *testing.T) {
	_, rt := b1Watch(t, b1Service("mc-java", map[string]string{
		"mc-router.itzg.me/externalServerName": "java.uniz.host",
	}, core.ServicePort{Name: "minecraft", Port: 25565}, b1NNPort()))

	_, ok := rt.ByHost("java.uniz.host")
	assert.False(t, ok)
}

func TestDiscoveryRemovesOnEmptyServerName(t *testing.T) {
	client, rt := b1Watch(t, b1Service("mc-a", b1Published(), b1NNPort()))
	_, ok := rt.ByHost("survival.uniz.host")
	require.True(t, ok)

	// Ruling R9: unpublishing keeps the Service and its port, with the annotations set to "".
	unpublished := b1Service("mc-a", map[string]string{
		"nethernet.uniz.host/serverName": "",
		"nethernet.uniz.host/legacyPort": "",
		"nethernet.uniz.host/asleepMotd": "",
		"nethernet.uniz.host/serverId":   "",
	}, b1NNPort())
	_, err := client.CoreV1().Services(b1Namespace).Update(context.Background(), unpublished, metav1.UpdateOptions{})
	require.NoError(t, err)

	b1Eventually(t, func() bool { _, ok := rt.ByHost("survival.uniz.host"); return !ok }, "empty serverName unroutes")
	_, ok = rt.ByLegacyPort(30017)
	assert.False(t, ok)
}

func TestDiscoveryNeedsTheNethernetPort(t *testing.T) {
	_, rt := b1Watch(t, b1Service("mc-a", b1Published(), core.ServicePort{Name: "minecraft", Port: 19132}))
	_, ok := rt.ByHost("survival.uniz.host")
	assert.False(t, ok)
}

func TestDiscoveryNeedsAClusterIP(t *testing.T) {
	svc := b1Service("mc-a", b1Published(), b1NNPort())
	svc.Spec.ClusterIP = core.ClusterIPNone
	_, rt := b1Watch(t, svc)
	_, ok := rt.ByHost("survival.uniz.host")
	assert.False(t, ok)
}

func TestDiscoveryReadsAnInvalidLegacyPortAsZero(t *testing.T) {
	ann := b1Published()
	ann["nethernet.uniz.host/legacyPort"] = "not-a-port"
	_, rt := b1Watch(t, b1Service("mc-a", ann, b1NNPort()))
	b, ok := rt.ByHost("survival.uniz.host")
	require.True(t, ok)
	assert.Equal(t, 0, b.LegacyPort)
}

func TestDiscoveryOnlyWatchesItsNamespace(t *testing.T) {
	other := b1Service("mc-a", b1Published(), b1NNPort())
	other.Namespace = "default"
	client := fake.NewClientset()
	_, err := client.CoreV1().Services("default").Create(context.Background(), other, metav1.CreateOptions{})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := NewRouteTable()
	require.NoError(t, WatchServices(ctx, client, b1Namespace, rt))
	_, ok := rt.ByHost("survival.uniz.host")
	assert.False(t, ok)
}

func b1Slice(name, svc string, eps ...discoveryv1.Endpoint) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: b1Namespace,
			Labels: map[string]string{discoveryv1.LabelServiceName: svc},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   eps,
	}
}

func b1Endpoint(ip string, ready *bool) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{Addresses: []string{ip}, Conditions: discoveryv1.EndpointConditions{Ready: ready}}
}

func b1PodIPs(rt *RouteTable) []netip.Addr {
	b, _ := rt.ByHost("survival.uniz.host")
	return b.PodIPs
}

func b1CreateSlice(t *testing.T, client *fake.Clientset, s *discoveryv1.EndpointSlice) {
	t.Helper()
	_, err := client.DiscoveryV1().EndpointSlices(b1Namespace).Create(context.Background(), s, metav1.CreateOptions{})
	require.NoError(t, err)
}

func TestDiscoveryFillsPodIPsFromReadyEndpoints(t *testing.T) {
	client, rt := b1Watch(t, b1Service("mc-a", b1Published(), b1NNPort()))
	yes := true
	b1CreateSlice(t, client, b1Slice("mc-a-1", "mc-a", b1Endpoint("10.244.3.17", &yes), b1Endpoint("10.244.3.18", nil)))
	b1CreateSlice(t, client, b1Slice("other-1", "mc-other", b1Endpoint("10.244.9.9", &yes)))

	want := []netip.Addr{netip.MustParseAddr("10.244.3.17"), netip.MustParseAddr("10.244.3.18")}
	b1Eventually(t, func() bool { return assert.ObjectsAreEqual(want, b1PodIPs(rt)) }, "ready (and nil-ready) endpoints fill PodIPs")
	b, _ := rt.ByHost("survival.uniz.host")
	assert.Equal(t, netip.MustParseAddrPort("10.96.1.7:19132"), b.Addr, "Addr stays the ClusterIP")
}

func TestDiscoveryDropsNotReadyEndpoints(t *testing.T) {
	no, yes := false, true
	client := fake.NewClientset()
	_, err := client.CoreV1().Services(b1Namespace).Create(context.Background(), b1Service("mc-a", b1Published(), b1NNPort()), metav1.CreateOptions{})
	require.NoError(t, err)
	b1CreateSlice(t, client, b1Slice("mc-a-1", "mc-a", b1Endpoint("10.244.3.17", &no), b1Endpoint("10.244.3.19", &yes)))
	v6 := b1Slice("mc-a-2", "mc-a", b1Endpoint("fd00::17", &yes))
	v6.AddressType = discoveryv1.AddressTypeIPv6
	b1CreateSlice(t, client, v6)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := NewRouteTable()
	require.NoError(t, WatchServices(ctx, client, b1Namespace, rt))
	b1Eventually(t, func() bool {
		return assert.ObjectsAreEqual([]netip.Addr{netip.MustParseAddr("10.244.3.19")}, b1PodIPs(rt))
	}, "only the ready IPv4 endpoint counts")
}

func TestDiscoveryUpdatesPodIPsWhenTheSliceChanges(t *testing.T) {
	client, rt := b1Watch(t, b1Service("mc-a", b1Published(), b1NNPort()))
	yes, no := true, false
	b1CreateSlice(t, client, b1Slice("mc-a-1", "mc-a", b1Endpoint("10.244.3.17", &yes)))
	b1Eventually(t, func() bool { return len(b1PodIPs(rt)) == 1 }, "first pod IP")

	_, err := client.DiscoveryV1().EndpointSlices(b1Namespace).Update(context.Background(),
		b1Slice("mc-a-1", "mc-a", b1Endpoint("10.244.5.2", &yes)), metav1.UpdateOptions{})
	require.NoError(t, err)
	b1Eventually(t, func() bool {
		return assert.ObjectsAreEqual([]netip.Addr{netip.MustParseAddr("10.244.5.2")}, b1PodIPs(rt))
	}, "a rescheduled pod's new IP replaces the old one")

	_, err = client.DiscoveryV1().EndpointSlices(b1Namespace).Update(context.Background(),
		b1Slice("mc-a-1", "mc-a", b1Endpoint("10.244.5.2", &no)), metav1.UpdateOptions{})
	require.NoError(t, err)
	b1Eventually(t, func() bool { _, ok := rt.ByHost("survival.uniz.host"); return ok && len(b1PodIPs(rt)) == 0 }, "not ready empties PodIPs, the route stays")

	require.NoError(t, client.DiscoveryV1().EndpointSlices(b1Namespace).Delete(context.Background(), "mc-a-1", metav1.DeleteOptions{}))
	b1Eventually(t, func() bool { _, ok := rt.ByHost("survival.uniz.host"); return ok && len(b1PodIPs(rt)) == 0 }, "deleted slice")
}

func TestDiscoveryRoutesAServiceBeforeItsSlicesExist(t *testing.T) {
	_, rt := b1Watch(t, b1Service("mc-a", b1Published(), b1NNPort()))
	b, ok := rt.ByHost("survival.uniz.host")
	require.True(t, ok, "an asleep server still routes so a join can wake it")
	assert.Empty(t, b.PodIPs)
}

// M-3: a missing RBAC rule must show in the logs, naming what is unsynced.
// B-I M-2: the test owns the tick, and sends it only after the services
// handler has applied its initial list, so the outcome never depends on timing.
func TestDiscoveryWarnsWhileACacheStaysUnsynced(t *testing.T) {
	hook := logrustest.NewGlobal()
	t.Cleanup(func() { logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{}) })
	ticks := make(chan time.Time)
	old := syncWarnTicks
	syncWarnTicks = func() (<-chan time.Time, func()) { return ticks, func() {} }
	t.Cleanup(func() { syncWarnTicks = old })

	client := fake.NewClientset()
	_, err := client.CoreV1().Services(b1Namespace).Create(context.Background(),
		b1Service("mc-a", b1Published(), b1NNPort()), metav1.CreateOptions{})
	require.NoError(t, err)
	client.PrependReactor("list", "endpointslices", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "discovery.k8s.io", Resource: "endpointslices"}, "", errors.New("no RBAC rule"))
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := NewRouteTable()
	done := make(chan error, 1)
	go func() { done <- WatchServices(ctx, client, b1Namespace, rt) }()

	b1Eventually(t, func() bool { _, ok := rt.ByHost("survival.uniz.host"); return ok },
		"the services handler applied its initial list")
	ticks <- time.Now()
	warned := func() (named []string) {
		for _, e := range hook.AllEntries() {
			if e.Level == logrus.WarnLevel {
				named = append(named, fmt.Sprint(e.Data["resource"]))
			}
		}
		return named
	}
	// The loop checks services before endpointslices, so a wrongly named
	// services would be the first warning of the tick.
	b1Eventually(t, func() bool { return len(warned()) > 0 }, "the tick warns")
	assert.Equal(t, []string{"endpointslices"}, warned(), "only the unsynced resource is named")

	cancel()
	assert.Error(t, <-done, "the wait still ends only with ctx")
}
