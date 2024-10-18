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
  IconButton,
  Tooltip,
  Typography
} from '@mui/material';
import { useTranslation } from 'react-i18next';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import { useState } from 'react';

type Props = {
  title: string
  date: Date
  dialogOpen: boolean
  setDialogOpen: React.Dispatch<React.SetStateAction<boolean>>
}

export const TimestampDialog: React.FC<Props> = ({
  title,
  date,
  dialogOpen,
  setDialogOpen
}) => {

  const { t } = useTranslation();
  const [copyLabel, setCopyLabel] = useState('copyToClipboard');

  return (
    <Dialog
      onClose={() => setDialogOpen(false)}
      open={dialogOpen}
      maxWidth="lg"
    >
      <DialogTitle sx={{ textAlign: 'center' }}>
        {title}
      </DialogTitle>
      <DialogContent>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <Typography sx={{ textAlign: 'center' }} color="textSecondary">{date.toISOString()}</Typography>
          <Tooltip title={t(copyLabel)} arrow placement="right" onMouseLeave={() => setTimeout(() => setCopyLabel('copyToClipboard'), 200)}>
            <IconButton onClick={() => { navigator.clipboard.writeText(date.toISOString()); setCopyLabel('copied') }}>
              <ContentCopyIcon />
            </IconButton>
          </Tooltip>
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
