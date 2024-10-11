/*
Copyright 2024.

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
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func mergeServicePorts(svcSpec *corev1.ServiceSpec, requiredPorts []corev1.ServicePort) {
	portsByName := map[string]*corev1.ServicePort{}
	for _, providedPort := range svcSpec.Ports {
		portsByName[providedPort.Name] = &providedPort
	}
	for _, requiredPort := range requiredPorts {
		providedPort, isProvided := portsByName[requiredPort.Name]
		if !isProvided {
			// Just use our definition
			portsByName[requiredPort.Name] = &requiredPort
		} else {
			// We own the target port number and protocol always
			providedPort.TargetPort = requiredPort.TargetPort
			providedPort.Protocol = requiredPort.Protocol
			// Port can be overridden
			if providedPort.Port == 0 {
				providedPort.Port = requiredPort.Port
			}
		}
	}
	portNames := make([]string, 0, len(portsByName))
	for portName := range portsByName {
		portNames = append(portNames, portName)
	}
	// Need to sort by name to give deterministic behavior
	sort.Strings(portNames)
	svcSpec.Ports = make([]corev1.ServicePort, len(portNames))
	for i, portName := range portNames {
		svcSpec.Ports[i] = *portsByName[portName]
	}
}

func reconcileEveryChange() builder.Predicates {
	return builder.WithPredicates(predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return true
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return true
		},
	})
}

// Having our CR list objects conform to this interface helps us implement generic
// functions like reconcileAll
type CRList[CR any] interface {
	client.ObjectList
	ItemsArray() []CR                // pointer to the .Items array
	AsObject(item *CR) client.Object // cast the pointer to an item to a client.Object to get the name/namespace
}

// This helper reconciles all objects in the current namespace
func reconcileAll[CR any, ListType CRList[CR]](c client.Client) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, object client.Object) []reconcile.Request {
		ns := object.GetNamespace()

		var l ListType
		err := c.List(ctx, l, client.InNamespace(ns))
		if err != nil {
			return nil
		}

		items := l.ItemsArray()
		if len(items) < 1 {
			return nil
		}
		requests := make([]reconcile.Request, len(items))

		for i, item := range items {
			obj := l.AsObject(&item)
			requests[i] = reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      obj.GetName(),
					Namespace: obj.GetNamespace(),
				},
			}
		}
		return requests
	})
}
