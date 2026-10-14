package nethernet

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
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
