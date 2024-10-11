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

package v1alpha1

import "sigs.k8s.io/controller-runtime/pkg/client"

// This mapping object for each CR type between the CR, pointer to the CR, and
// list of items for the CR, lets us build generic functions.
type CRMap[CR any, PCR client.Object, CRL client.ObjectList] struct {
	NewList  func() CRL
	ItemsFor func(list CRL) []CR
	AsObject func(item *CR) PCR
}
