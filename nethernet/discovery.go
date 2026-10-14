package nethernet

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	core "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
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

// syncWarnEvery spaces the startup warnings that name an unsynced informer
// cache (a missing RBAC rule otherwise hangs startup silently).
var syncWarnEvery = 30 * time.Second

type serviceRoutes struct {
	mu       sync.Mutex // one apply at a time, so the last apply reads the newest caches
	table    *RouteTable
	services corelisters.ServiceLister
	slices   discoverylisters.EndpointSliceLister
}

// WatchServices keeps t in step with the annotated Services in namespace and
// their EndpointSlices (for the pod IPs). It returns once both event handlers
// have applied the initial lists, so the table is full; the watches run until
// ctx ends. While a cache stays unsynced it warns every syncWarnEvery.
func WatchServices(ctx context.Context, client kubernetes.Interface, namespace string, t *RouteTable) error {
	factory := informers.NewSharedInformerFactoryWithOptions(client, 0, informers.WithNamespace(namespace))
	svcInformer := factory.Core().V1().Services()
	sliceInformer := factory.Discovery().V1().EndpointSlices()
	r := &serviceRoutes{table: t, services: svcInformer.Lister(), slices: sliceInformer.Lister()}

	svcReg, err := svcInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { r.applyKey(obj) },
		UpdateFunc: func(_, obj any) { r.applyKey(obj) },
		DeleteFunc: func(obj any) { r.applyKey(obj) },
	})
	if err != nil {
		return err
	}
	sliceReg, err := sliceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { r.applySlice(obj) },
		UpdateFunc: func(_, obj any) { r.applySlice(obj) },
		DeleteFunc: func(obj any) { r.applySlice(obj) },
	})
	if err != nil {
		return err
	}
	factory.Start(ctx.Done())

	// The handlers' HasSynced, not the informers': only it says the initial
	// list has gone through apply (client-go shared_informer.go).
	synced := make(chan bool, 1)
	go func() { synced <- cache.WaitForCacheSync(ctx.Done(), svcReg.HasSynced, sliceReg.HasSynced) }()
	tick := time.NewTicker(syncWarnEvery)
	defer tick.Stop()
	for {
		select {
		case ok := <-synced:
			if !ok {
				return errors.New("nethernet: service/endpointslice informers did not sync")
			}
			return nil
		case <-tick.C:
			for _, c := range []struct {
				resource string
				reg      cache.ResourceEventHandlerRegistration
			}{{"services", svcReg}, {"endpointslices", sliceReg}} {
				if !c.reg.HasSynced() {
					logrus.WithField("resource", c.resource).
						Warn("nethernet: informer cache still unsynced; check the router's RBAC for this resource")
				}
			}
		}
	}
}

func (r *serviceRoutes) applyKey(obj any) {
	key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
	if err != nil {
		return
	}
	ns, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return
	}
	r.apply(ns, name)
}

func (r *serviceRoutes) applySlice(obj any) {
	if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = d.Obj
	}
	s, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok || s.Labels[discoveryv1.LabelServiceName] == "" {
		return
	}
	r.apply(s.Namespace, s.Labels[discoveryv1.LabelServiceName])
}

// apply recomputes one Service's route from the informer caches, which are
// updated before handlers run: reading them (not the event) means events from
// the two informers can interleave in any order.
func (r *serviceRoutes) apply(namespace, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := namespace + "/" + name
	svc, err := r.services.Services(namespace).Get(name)
	if err != nil {
		r.table.Remove(key)
		return
	}
	hosts, b, ok := backendOf(svc)
	if !ok {
		r.table.Remove(key)
		return
	}
	b.PodIPs = r.readyPodIPs(namespace, name)
	logrus.WithFields(logrus.Fields{"service": key, "hosts": hosts, "addr": b.Addr, "pods": b.PodIPs}).
		Debug("nethernet: route")
	r.table.Upsert(key, hosts, b)
}

// readyPodIPs returns the sorted IPv4 addresses of the Service's endpoints
// whose ready condition is true or unset.
func (r *serviceRoutes) readyPodIPs(namespace, name string) []netip.Addr {
	sel := labels.SelectorFromSet(labels.Set{discoveryv1.LabelServiceName: name})
	list, err := r.slices.EndpointSlices(namespace).List(sel)
	if err != nil {
		return nil
	}
	var ips []netip.Addr
	for _, s := range list {
		if s.AddressType != discoveryv1.AddressTypeIPv4 {
			continue
		}
		for _, ep := range s.Endpoints {
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}
			for _, a := range ep.Addresses {
				if ip, err := netip.ParseAddr(a); err == nil && ip.Is4() {
					ips = append(ips, ip)
				}
			}
		}
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	return slices.Compact(ips)
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
