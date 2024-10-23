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
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle} from '@mui/material';
import { useTranslation } from 'react-i18next';
import JSONPretty from 'react-json-pretty';
import { IPaladinTransaction } from '../interfaces';

type Props = {
  paladinTransaction: IPaladinTransaction
  dialogOpen: boolean
  setDialogOpen: React.Dispatch<React.SetStateAction<boolean>>
}

export const PaladinTransactionDialog: React.FC<Props> = ({
  paladinTransaction,
  dialogOpen,
  setDialogOpen
}) => {

  const { t } = useTranslation();

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
        <JSONPretty style={{ fontSize: '14px'}}  data={paladinTransaction} theme={{
          main: 'line-height:1.3;color:#107070;overflow:auto;',
          key: 'color:#464646;',
          string: 'color:#107070;',
          value: 'color:#107070;',
          boolean: 'color:#107070;'
        }} />
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
