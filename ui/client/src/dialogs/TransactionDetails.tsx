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

import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  useTheme
} from '@mui/material';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import JSONPretty from 'react-json-pretty';
import { fetchStateReceipt } from '../queries/states';
import { IPaladinTransaction } from '../interfaces';
import { fetchDomainReceipt } from '../queries/domains';
import { fetchTransactionReceipt } from '../queries/transactions';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';

type Props = {
  paladinTransaction: IPaladinTransaction
  dialogOpen: boolean
  setDialogOpen: React.Dispatch<React.SetStateAction<boolean>>
}

export const PaladinTransactionDetailsDialog: React.FC<Props> = ({
  paladinTransaction,
  dialogOpen,
  setDialogOpen
}) => {

  const { t } = useTranslation();
  const theme = useTheme();

  const { data: transactionReceipt } = useQuery({
    queryKey: ["ptx_getTransactionReceipt", paladinTransaction],
    queryFn: () => fetchTransactionReceipt(paladinTransaction.id),
    retry: false,
    enabled: dialogOpen
  });

  const { data: stateReceipt } = useQuery({
    queryKey: ["stateReceipt", paladinTransaction],
    queryFn: () => fetchStateReceipt(paladinTransaction.id),
    retry: false,
    enabled: dialogOpen
  });

  const { data: domainReceipt } = useQuery({
    queryKey: ["domainReceipt", paladinTransaction],
    queryFn: () => fetchDomainReceipt(paladinTransaction.domain, paladinTransaction.id),
    retry: false,
    enabled: dialogOpen
  });

  const colors = theme.palette.mode === 'dark' ?
    {
      main: 'line-height:1.3;color:#white;overflow:auto;',
      key: 'color:white;',
      string: 'color:#20dfdf;',
      value: 'color:#20dfdf;',
      boolean: 'color:#20dfdf;'
    } :
    {
      main: 'line-height:1.3;color:#107070;overflow:auto;',
      key: 'color:#464646;',
      string: 'color:#107070;',
      value: 'color:#107070;',
      boolean: 'color:#107070;'
    };

  return (
    <Dialog
      onClose={() => setDialogOpen(false)}
      open={dialogOpen}
      maxWidth="lg"
    >
      <DialogTitle sx={{ textAlign: 'center' }}>
        {t('transaction')}
      </DialogTitle>
      <DialogContent>
        <Accordion defaultExpanded={true}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            {t('details')}
          </AccordionSummary>
          <AccordionDetails >
            <JSONPretty style={{ fontSize: '14px' }} data={paladinTransaction} theme={colors} />
          </AccordionDetails>
        </Accordion>
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            {t('receipt')}
          </AccordionSummary>
          <AccordionDetails >
            <JSONPretty style={{ fontSize: '14px' }} data={transactionReceipt} theme={colors} />
          </AccordionDetails>
        </Accordion>
        {!(stateReceipt?.none === true) &&
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              {t('stateReceipt')}
            </AccordionSummary>
            <AccordionDetails >
              <JSONPretty style={{ fontSize: '14px' }} data={stateReceipt} theme={colors} />
            </AccordionDetails>
          </Accordion>}
        {domainReceipt !== undefined &&
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              {t('domainReceipt')}
            </AccordionSummary>
            <AccordionDetails >
              <JSONPretty style={{ fontSize: '14px' }} data={domainReceipt} theme={colors} />
            </AccordionDetails>
          </Accordion>}
      </DialogContent>
      <DialogActions sx={{ justifyContent: 'center', marginBottom: '15px' }}>
        <Button
          onClick={() => setDialogOpen(false)}
          size="large"
          variant="contained"
          disableElevation>
          {t('dismiss')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};
