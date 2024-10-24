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
import { Box, Grid2, TextField, Typography } from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import { t } from "i18next";
import { fetchRegistryEntries } from "../queries/registry";
import { Hash } from "./Hash";

type Props = {
  registryName: string;
};

export const Registry: React.FC<Props> = ({ registryName }) => {
  const { data: registryEntries } = useQuery({
    queryKey: ["registryEntries", registryName],
    queryFn: () =>
      fetchRegistryEntries(registryName).then((entries) =>
        entries.sort((a, b) => (a.name < b.name ? -1 : 0))
      ),
  });

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
    <Box>
      {registryEntries
        ?.filter((registryEntry) => registryEntry.name !== "root")
        .map((registryEntry) => (
          <Box
            key={registryEntry.id}
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
              {Object.keys(registryEntry.properties)
                .filter((property) => property !== "$owner")
                .map((property) => (
                  <TextField
                    key={property}
                    label={property}
                    disabled
                    maxRows={8}
                    multiline
                    fullWidth
                    size="small"
                    value={processValue(registryEntry.properties[property])}
                  />
                ))}
            </Grid2>
          </Box>
        ))}
    </Box>
  );
};
