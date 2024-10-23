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

import { IPaladinTransaction } from "../interfaces";
import { t } from "i18next";
import { Hash } from "./Hash";
import { Box, ButtonBase, Grid2, TextField, Typography } from "@mui/material";
import { Timestamp } from "./Timestamp";
import { useState } from "react";
import { PaladinTransactionDialog } from "../dialogs/PaladinTransaction";

type Props = {
  paladinTransaction: IPaladinTransaction
};

export const PendingTransaction: React.FC<Props> = ({ paladinTransaction }) => {

  if(paladinTransaction === undefined) {
    return <></>
  }

  const [paladinTransactionDialogOpen, setPaladinTransactionDialogOpen] = useState(false);

  return (
    <>
      <Box sx={{
        backgroundColor: theme => theme.palette.background.paper,
        marginBottom: '20px', padding: '10px', borderRadius: '6px', boxShadow: '0px 0px 8px 3px rgba(0,0,0,0.26)'
      }}>
        <Grid2 container direction="column" spacing={2}>
          <Grid2 container justifyContent="space-evenly">
            <Grid2>
              <ButtonBase onClick={() => setPaladinTransactionDialogOpen(true)}>
                <Typography align="center" variant="h6" color="primary">{t(paladinTransaction.type)}</Typography>
              </ButtonBase>
              <Typography align="center" variant="body2" color="textSecondary">{t('type')}</Typography>
            </Grid2>
            <Grid2 textAlign="center">
              <Timestamp date={new Date(paladinTransaction.created)} />
              <Typography align="center" variant="body2" color="textSecondary">{t('created')}</Typography>
            </Grid2>
            <Grid2 textAlign="center">
              <Hash title={t('id')} hash={paladinTransaction.id} />
              <Typography align="center" variant="body2" color="textSecondary">{t('id')}</Typography>
            </Grid2>
            <Grid2>
              <Typography align="center" variant="h6" color="textPrimary">{paladinTransaction.domain}</Typography>
              <Typography align="center" variant="body2" color="textSecondary">{t('domain')}</Typography>
            </Grid2>
            <Grid2>
              <Typography align="center" variant="h6" color="textPrimary">{t(paladinTransaction.from)}</Typography>
              <Typography align="center" variant="body2" color="textSecondary">{t('from')}</Typography>
            </Grid2>
            <Grid2>
              <Typography align="center" variant="h6" color="textPrimary">{t(paladinTransaction.type)}</Typography>
              <Typography align="center" variant="body2" color="textSecondary">{t('type')}</Typography>
            </Grid2>
            {Object.keys(paladinTransaction.data).filter(property => property !== '$owner').map(property =>
              <TextField key={property} label={property} disabled maxRows={8} multiline fullWidth size="small"
                value={JSON.stringify(paladinTransaction.data[property])} />
            )}
          </Grid2>
        </Grid2>
      </Box>
      <PaladinTransactionDialog
        paladinTransaction={paladinTransaction}
        dialogOpen={paladinTransactionDialogOpen}
        setDialogOpen={setPaladinTransactionDialogOpen}
      />
    </>
  );

}