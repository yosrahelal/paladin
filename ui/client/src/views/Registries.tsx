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

import { Box, Fade, Paper, Typography, useTheme } from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import { t } from "i18next";
import { useContext } from "react";
import { Registry } from "../components/Registry";
import { ApplicationContext } from "../contexts/ApplicationContext";
import { fetchRegistries } from "../queries/registry";
import { altDarkModeScrollbarStyle, altLightModeScrollbarStyle } from "../themes/default";

export const Registries: React.FC = () => {
  const { lastBlockWithTransactions } = useContext(ApplicationContext);

  const theme = useTheme();
  const addedStyle = theme.palette.mode === 'light'? altLightModeScrollbarStyle : altDarkModeScrollbarStyle;

  const { data: registries } = useQuery({
    queryKey: ["registries", lastBlockWithTransactions],
    queryFn: () => fetchRegistries(),
    retry: false
  });

  return (
    <Fade timeout={600} in={true}>
      <Box
        sx={{
          padding: "20px",
          maxWidth: "1300px",
          marginLeft: "auto",
          marginRight: "auto",
        }}
      >
        <Paper
          sx={{
            padding: "10px",
            paddingTop: "12px",
            backgroundColor: theme => theme.palette.mode === 'light' ?
            'rgba(255, 255, 255, .65)' : 'rgba(60, 60, 60, .65)'
          }}
        >
          <Typography align="center" sx={{ fontSize: "24px", fontWeight: 500 }}>
            {t("entries")}
          </Typography>
          <Box
            sx={{
              padding: "20px",
              height: "calc(100vh - 162px)",
              ...addedStyle
            }}
          >
            {registries?.map((registry) => (
              <Registry key={registry} registryName={registry} />
            ))}
          </Box>
        </Paper>
      </Box>
    </Fade>
  );
};
