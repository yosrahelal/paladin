// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import {
  Accordion,
  AccordionDetails,
  AccordionSummary
} from '@mui/material';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { IPaladinTransaction } from '../interfaces';
import { fetchDomainReceipt } from '../queries/domains';
import { fetchStateReceipt } from '../queries/states';
import { fetchTransactionReceipt } from '../queries/transactions';
import { JSONBox } from './JSONBox';
import { EVMPrivateDetails } from './EVMPrivateDetails';

type Props = {
  paladinTransaction: IPaladinTransaction
}

export const PaladinTransactionsDetails: React.FC<Props> = ({
  paladinTransaction
}) => {

  const { t } = useTranslation();

  const { data: transactionReceipt } = useQuery({
    queryKey: ["ptx_getTransactionReceipt", paladinTransaction],
    queryFn: () => fetchTransactionReceipt(paladinTransaction.id),
    retry: false
  });

  const { data: stateReceipt } = useQuery({
    queryKey: ["stateReceipt", paladinTransaction],
    queryFn: () => fetchStateReceipt(paladinTransaction.id),
    retry: false
  });

  const { data: domainReceipt } = useQuery({
    queryKey: ["domainReceipt", paladinTransaction],
    queryFn: () => fetchDomainReceipt(paladinTransaction.domain, paladinTransaction.id),
    retry: false
  });

  return (
    <>
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          {t('details')}
        </AccordionSummary>
        <AccordionDetails >
          <JSONBox data={paladinTransaction} />
        </AccordionDetails>
      </Accordion>
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          {t('receipt')}
        </AccordionSummary>
        <AccordionDetails >
          <JSONBox data={transactionReceipt} />
        </AccordionDetails>
      </Accordion>
      {domainReceipt !== undefined && <>
        <EVMPrivateDetails transactionId={paladinTransaction.id} domainReceipt={domainReceipt}/>
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            {t('domainReceipt')}
          </AccordionSummary>
          <AccordionDetails >
            <JSONBox data={domainReceipt} />
          </AccordionDetails>
        </Accordion>
      </>}
      {!(stateReceipt?.none === true) &&
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            {t('stateReceipt')}
          </AccordionSummary>
          <AccordionDetails >
            <JSONBox data={stateReceipt} />
          </AccordionDetails>
        </Accordion>}
    </>
  );
};
