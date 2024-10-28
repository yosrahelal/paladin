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

import { Box, Button, Collapse, Grid2, TextField, Typography } from "@mui/material";
import { t } from "i18next";
import { useState } from "react";
import { IPaladinTransaction } from "../interfaces";
import { Hash } from "./Hash";
import { Timestamp } from "./Timestamp";
import daysjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import { EllapsedTime } from "./EllapsedTime";
import VisibilityIcon from '@mui/icons-material/Visibility';
import { PaladinTransactionDetailsDialog } from "../dialogs/TransactionDetails";

daysjs.extend(relativeTime);

type Props = {
  paladinTransaction: IPaladinTransaction;
};

export const PendingTransaction: React.FC<Props> = ({ paladinTransaction }) => {

  const [viewDetailsDialogOpen, setViewDetailsDialogOpen] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);


  if (paladinTransaction === undefined) {
    return <></>;
  }

  const formatProperty = (value: any) => {
    try {
      const parsed = JSON.stringify(value);
      return parsed.substring(1, parsed.length - 1);
    } catch (err) { }
    return value;
  };

  return (
    <>
      <Box
        sx={{
          backgroundColor: (theme) => theme.palette.background.paper,
          marginBottom: "20px",
          padding: "10px",
          borderRadius: "6px",
          boxShadow: "0px 0px 8px 3px rgba(0,0,0,0.26)",
        }}
      >

        <Grid2 container direction="column" spacing={2}>
          <Grid2 container justifyContent="space-evenly">
            <Grid2>
              <Typography align="center" variant="h6">
                {t(paladinTransaction.type)}
              </Typography>
              <Typography align="center" variant="body2" color="textSecondary">
                {t("type")}
              </Typography>
            </Grid2>
            <Grid2 textAlign="center">
              <Timestamp date={new Date(paladinTransaction.created)} />
              <Typography align="center" variant="body2" color="textSecondary">
                {t("created")}
              </Typography>
            </Grid2>
            <Grid2 textAlign="center">
              <Hash title={t("id")} hash={paladinTransaction.id} />
              <Typography align="center" variant="body2" color="textSecondary">
                {t("id")}
              </Typography>
            </Grid2>
            <Grid2>
              <Typography align="center" variant="h6" color="textPrimary">
                {paladinTransaction.domain ?? '--'}
              </Typography>
              <Typography align="center" variant="body2" color="textSecondary">
                {t("domain")}
              </Typography>
            </Grid2>
            <Grid2>
              <Typography align="center" variant="h6" color="textPrimary">
                {t(paladinTransaction.from)}
              </Typography>
              <Typography align="center" variant="body2" color="textSecondary">
                {t("from")}
              </Typography>
            </Grid2>
            <Grid2>
              <Typography align="center" variant="h6" color="textPrimary">
                {t(paladinTransaction.type)}
              </Typography>
              <Typography align="center" variant="body2" color="textSecondary">
                {t("type")}
              </Typography>
            </Grid2>
          </Grid2>
          <Grid2>
            <Box sx={{ display: 'flex', padding: '4px', justifyContent: 'space-between' }}>
              <EllapsedTime timestamp={paladinTransaction?.created} />
              <Box>
                <Button size="small" startIcon={<VisibilityIcon />} sx={{ marginRight: '40px' }}
                  onClick={() => setViewDetailsDialogOpen(true)}>{t('viewDetails')}</Button>
                <Button size="small" endIcon={isExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                  onClick={() => setIsExpanded(!isExpanded)}>
                  {t(isExpanded ? 'hideProperties' : 'showProperties')}
                </Button>
              </Box>
            </Box>
            <Collapse in={isExpanded}>
              {Object.keys(paladinTransaction.data)
                .filter((property) => property !== "$owner")
                .map((property) => (
                  <TextField
                    key={property}
                    label={property}
                    maxRows={8}
                    multiline
                    fullWidth
                    size="small"
                    sx={{ marginTop: '12px' }}
                    value={formatProperty(paladinTransaction.data[property])}
                  />
                ))}
              {Object.keys(paladinTransaction.data).length === 0 &&
                <Typography align="center">{t('noProperties')}</Typography>}
            </Collapse>
          </Grid2>
        </Grid2>
      </Box>
      <PaladinTransactionDetailsDialog
        paladinTransaction={paladinTransaction}
        dialogOpen={viewDetailsDialogOpen}
        setDialogOpen={setViewDetailsDialogOpen}
      />
    </>
  );
};
