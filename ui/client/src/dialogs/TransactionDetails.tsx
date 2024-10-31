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
  DialogTitle,
  MenuItem,
  TextField,
  useTheme
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import { IPaladinTransaction } from '../interfaces';
import { PaladinTransactionsDetails } from '../components/TransactionDetails';
import { useEffect, useState } from 'react';
import { altLightModeScrollbarStyle, altDarkModeScrollbarStyle } from '../themes/default';

type Props = {
  paladinTransactions: IPaladinTransaction[]
  dialogOpen: boolean
  setDialogOpen: React.Dispatch<React.SetStateAction<boolean>>
}

export const PaladinTransactionsDetailsDialog: React.FC<Props> = ({
  paladinTransactions,
  dialogOpen,
  setDialogOpen
}) => {

  const [selectedPaladinTransactionIndex, setSelectedPaladinTransactionIndex] = useState(0);
  const { t } = useTranslation();

  const theme = useTheme();
  const addedStyle = theme.palette.mode === 'light'? altLightModeScrollbarStyle : altDarkModeScrollbarStyle;


  useEffect(() => {
    if (dialogOpen) {
      setSelectedPaladinTransactionIndex(0);
    }
  }, [dialogOpen]);

  return (
    <Dialog
      onClose={() => setDialogOpen(false)}
      open={dialogOpen}
      fullWidth
      maxWidth="xl"
    >
      <DialogTitle sx={{ textAlign: 'center' }}>
        {t('transaction')}
      </DialogTitle>
      <DialogContent sx={{ margin: '10px', padding: '10px', ...addedStyle}}>
        <TextField select label={t('id')} fullWidth size="small" sx={{ marginTop: '5px' }} value={selectedPaladinTransactionIndex}
          onChange={event => setSelectedPaladinTransactionIndex(Number(event.target.value))}>
          {paladinTransactions.map((paladinTransaction, index) =>
            <MenuItem key={paladinTransaction.id} value={index}>{paladinTransaction.id}</MenuItem>
          )}
        </TextField>
        <PaladinTransactionsDetails
          paladinTransaction={paladinTransactions[selectedPaladinTransactionIndex]}
        />
      </DialogContent>
      <DialogActions sx={{ justifyContent: 'center', marginBottom: '15px' }}>
        <Button
          onClick={() => setDialogOpen(false)}
          sx={{ textTransform: 'none' }}
          variant="contained"
          disableElevation>
          {t('dismiss')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};
