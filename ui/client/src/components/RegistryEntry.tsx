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

import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
import ErrorOutlineIcon from "@mui/icons-material/ErrorOutline";
import { Box, Button, Collapse, Grid2, TextField, Typography } from "@mui/material";
import { t } from "i18next";
import { Hash } from "./Hash";
import { useState } from "react";
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import { IRegistryEntry } from "../interfaces";
import VisibilityIcon from '@mui/icons-material/Visibility';
import { ViewDetailsDialog } from "../dialogs/ViewDetails";

type Props = {
  registryEntry: IRegistryEntry;
};

export const RegistryEntry: React.FC<Props> = ({ registryEntry }) => {

  const [isExpanded, setIsExpanded] = useState(false);
  const [viewDetailsDialogOpen, setViewDetailsDialogOpen] = useState(false);

  const processValue = (value: string) => {
    try {
      const parsedValue = JSON.parse(value);
      return JSON.stringify(parsedValue, null, 8);
    } catch (err) {
      console.error(err);
    }
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
              <Typography align="center" variant="h6" color="textPrimary">
                {registryEntry.name}
              </Typography>
              <Typography
                align="center"
                variant="body2"
                color="textSecondary"
              >
                {t("name")}
              </Typography>
            </Grid2>
            <Grid2>
              <Typography align="center" variant="h6" color="textPrimary">
                {registryEntry.registry}
              </Typography>
              <Typography
                align="center"
                variant="body2"
                color="textSecondary"
              >
                {t("registry")}
              </Typography>
            </Grid2>
            <Grid2>
              <Hash title={t("id")} hash={registryEntry.id} />
              <Typography
                align="center"
                variant="body2"
                color="textSecondary"
              >
                {t("id")}
              </Typography>
            </Grid2>
            <Grid2>
              <Hash
                title={t("owner")}
                hash={registryEntry.properties.$owner}
              />
              <Typography
                align="center"
                variant="body2"
                color="textSecondary"
              >
                {t("owner")}
              </Typography>
            </Grid2>
            <Grid2 sx={{ textAlign: "center" }} alignContent="center">
              {registryEntry.active ? (
                <CheckCircleOutlineIcon color="primary" />
              ) : (
                <ErrorOutlineIcon color="error" />
              )}
              <Typography
                align="center"
                variant="body2"
                color="textSecondary"
              >
                {t("active")}
              </Typography>
            </Grid2>
          </Grid2>
          <Grid2>
            <Box sx={{ display: 'flex', padding: '4px', justifyContent: 'right' }}>
              <Button size="small" startIcon={<VisibilityIcon />} sx={{ marginRight: '40px' }}
                onClick={() => setViewDetailsDialogOpen(true)}>{t('viewDetails')}</Button>
              <Button size="small" endIcon={isExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                onClick={() => setIsExpanded(!isExpanded)}>
                {t(isExpanded ? 'hideProperties' : 'showProperties')}
              </Button>
            </Box>
            <Collapse in={isExpanded}>
              {Object.keys(registryEntry.properties)
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
                    value={processValue(registryEntry.properties[property])}
                  />
                ))}
            </Collapse>
          </Grid2>
        </Grid2>
      </Box>
      <ViewDetailsDialog
        title={t('registryEntry')}
        details={registryEntry}
        dialogOpen={viewDetailsDialogOpen}
        setDialogOpen={setViewDetailsDialogOpen}
      />
    </>
  );
};
