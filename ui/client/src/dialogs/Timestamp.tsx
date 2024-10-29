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
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Grid2,
  TextField
} from '@mui/material';
import { useTranslation } from 'react-i18next';

type Props = {
  timestamp: string
  dialogOpen: boolean
  setDialogOpen: React.Dispatch<React.SetStateAction<boolean>>
}

export const TimestampDialog: React.FC<Props> = ({
  timestamp,
  dialogOpen,
  setDialogOpen
}) => {

  const { t } = useTranslation();
  const date = new Date(timestamp);

  const getEpoch = () => {
    let epoch = date.getTime().toString();
    const length = timestamp.length;
    switch (length) {
      case 30:
        return t('numberNanoseconds', { number: epoch + timestamp.substring(26, 29) });
      case 25:
        return t('numberMilliseconds', { number: timestamp.substring(21, 24) });
      default:
        return t('numberSeconds', { number: epoch.substring(0, 10) });
    }
  };

  console.log(timestamp)

  return (
    <Dialog
      onClose={() => setDialogOpen(false)}
      open={dialogOpen}
      maxWidth="lg"
    >
      <DialogTitle sx={{ textAlign: 'center' }}>
        {t('timestamp')}
      </DialogTitle>
      <DialogContent>
        <Box sx={{ alignItems: 'center', minWidth: '300px', paddingTop: '5px' }}>
          <Grid2 container direction="column" spacing={2}>
            <Grid2>
              <TextField
                size="small"
                fullWidth
                label={t('localTime')}
                value={date.toLocaleString()}
              />
            </Grid2>
            <Grid2>
              <TextField
                size="small"
                fullWidth
                label={t('ISO')}
                value={timestamp}
              />
            </Grid2>
            <Grid2>
              <TextField
                size="small"
                fullWidth
                label={t('UTC')}
                value={date.toUTCString()}
              />
            </Grid2>
            <Grid2>
              <TextField
                size="small"
                fullWidth
                label={t('epoch')}
                value={getEpoch()}
              />
            </Grid2>
          </Grid2>
        </Box>
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
