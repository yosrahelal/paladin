/*
 * Copyright © 2024 Kaleido, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package privatetxnmgr

import (
	"context"

	"github.com/kaleido-io/paladin/toolkit/pkg/log"
	"github.com/kaleido-io/paladin/toolkit/pkg/prototk"
)

func (tf *transactionFlow) hasOutstandingVerifierRequests(ctx context.Context) bool {
	log.L(ctx).Debug("transactionFlow:hasOutstandingVerifierRequests")

	// assume they are all resolved until we find one in RequiredVerifiers that is not in Verifiers
	verifiersResolved := true
	for _, v := range tf.transaction.PreAssembly.RequiredVerifiers {
		thisVerifierIsResolved := false
		for _, rv := range tf.transaction.PreAssembly.Verifiers {
			if rv.Lookup == v.Lookup {
				thisVerifierIsResolved = true
				break
			}
		}
		if !thisVerifierIsResolved {
			verifiersResolved = false
		}
	}
	if verifiersResolved {
		return false
	} else {
		log.L(ctx).Infof("Waiting for verifiers to be resolved for transaction %s", tf.transaction.ID.String())
		return true
	}

}

func (tf *transactionFlow) hasOutstandingSignatureRequests() bool {
	outstandingSignatureRequests := false
out:
	for _, attRequest := range tf.transaction.PostAssembly.AttestationPlan {
		if attRequest.AttestationType == prototk.AttestationType_SIGN {
			found := false
			for _, signatures := range tf.transaction.PostAssembly.Signatures {
				if signatures.Name == attRequest.Name {
					found = true
					break
				}
			}
			if !found {
				outstandingSignatureRequests = true
				// no point checking any further, we have at least one outstanding signature request
				break out
			}
		}
	}
	return outstandingSignatureRequests
}

func (tf *transactionFlow) hasOutstandingEndorsementRequests(ctx context.Context) bool {
	return len(tf.outstandingEndorsementRequests(ctx)) > 0
}

type outstandingEndorsementRequest struct {
	attRequest *prototk.AttestationRequest
	party      string
}

func (tf *transactionFlow) outstandingEndorsementRequests(_ context.Context) []*outstandingEndorsementRequest {
	outstandingEndorsementRequests := make([]*outstandingEndorsementRequest, 0)
	for _, attRequest := range tf.transaction.PostAssembly.AttestationPlan {
		if attRequest.AttestationType == prototk.AttestationType_ENDORSE {
			for _, party := range attRequest.Parties {
				var verifier string
				for _, v := range tf.transaction.PreAssembly.Verifiers {
					if v.Lookup == party {
						verifier = v.Verifier
						break
					}
				}

				found := false
				for _, endorsement := range tf.transaction.PostAssembly.Endorsements {
					if endorsement.Name == attRequest.Name && endorsement.Verifier.Verifier == verifier {
						found = true
						break
					}
				}
				if !found {
					outstandingEndorsementRequests = append(outstandingEndorsementRequests, &outstandingEndorsementRequest{party: party, attRequest: attRequest})
				}
			}
		}
	}
	return outstandingEndorsementRequests
}
