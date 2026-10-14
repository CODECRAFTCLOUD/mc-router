package nethernet

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	core "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Annotations the API writes on a server's mc-<id> Service (uniz.host
// apps/api/src/shared/compute/k8s-manifests.ts). An unpublished server keeps
// the Service with all four set to "".
const (
	AnnotationServerName = "nethernet.uniz.host/serverName"
	AnnotationLegacyPort = "nethernet.uniz.host/legacyPort"
	AnnotationAsleepMOTD = "nethernet.uniz.host/asleepMotd"
	AnnotationServerID   = "nethernet.uniz.host/serverId"
	nethernetPortName    = "nethernet"
)

// WatchServices keeps t in step with the annotated Services in namespace. It
// returns once the initial list is loaded; the watch runs until ctx ends.
func WatchServices(ctx context.Context, client kubernetes.Interface, namespace string, t *RouteTable) error {
	factory := informers.NewSharedInformerFactoryWithOptions(client, 0, informers.WithNamespace(namespace))
	informer := factory.Core().V1().Services().Informer()
	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { applyService(t, obj) },
		UpdateFunc: func(_, obj any) { applyService(t, obj) },
		DeleteFunc: func(obj any) {
			if key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj); err == nil {
				t.Remove(key)
			}
		},
	})
	if err != nil {
		return err
	}
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		return errors.New("nethernet: service informer did not sync")
	}
	return nil
}

func applyService(t *RouteTable, obj any) {
	svc, ok := obj.(*core.Service)
	if !ok {
		return
	}
	key := svc.Namespace + "/" + svc.Name
	hosts, b, ok := backendOf(svc)
	if !ok {
		t.Remove(key)
		return
	}
	logrus.WithFields(logrus.Fields{"service": key, "hosts": hosts, "addr": b.Addr}).Debug("nethernet: route")
	t.Upsert(key, hosts, b)
}

// backendOf reads a Service's route: routable only with a non-empty serverName
// annotation, a port named "nethernet" and a ClusterIP.
func backendOf(svc *core.Service) ([]string, Backend, bool) {
	ann := svc.Annotations
	var hosts []string
	for _, h := range strings.Split(ann[AnnotationServerName], ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return nil, Backend{}, false
	}
	ip, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil {
		return nil, Backend{}, false
	}
	for _, p := range svc.Spec.Ports {
		if p.Name != nethernetPortName || p.Port <= 0 || p.Port > 65535 {
			continue
		}
		legacy, err := strconv.Atoi(ann[AnnotationLegacyPort])
		if err != nil || legacy < 0 || legacy > 65535 {
			legacy = 0
		}
		return hosts, Backend{
			ServerID:   ann[AnnotationServerID],
			Addr:       netip.AddrPortFrom(ip, uint16(p.Port)),
			LegacyPort: legacy,
			AsleepMOTD: ann[AnnotationAsleepMOTD],
		}, true
	}
	return nil, Backend{}, false
}
