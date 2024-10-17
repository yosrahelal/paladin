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

import { AppBar, Box, Grid2, Tab, Tabs, Toolbar, Typography } from "@mui/material";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";

export const Header: React.FC = () => {

  const [tab, setTab] = useState(0);
  const { t } = useTranslation();
  const navigate = useNavigate();

  useEffect(() => {
    switch (tab) {
      case 0: navigate('/transactions-and-events'); break;
      case 1: navigate('/registry'); break;
    }
  }, [tab]);

  return (
    <>
      <AppBar>
        <Toolbar>
          <Grid2 container alignItems="center" justifyContent="space-between" size={{ xs: 12 }}>
            <Grid2>
              <Typography variant="h6">{t('paladin')}</Typography>
            </Grid2>
            <Grid2>
              <Tabs value={tab} onChange={(_event, value) => setTab(value)} textColor="inherit"
                TabIndicatorProps={{
                  style: {
                    backgroundColor: 'white'
                  }
                }}
              >
                <Tab label={t('transactionsAndEvents')} />
                <Tab label={t('registry')} />
              </Tabs>
            </Grid2>
          </Grid2>
        </Toolbar>
      </AppBar>
      <Box sx={{ height: theme => theme.mixins.toolbar }} />
    </>
  );

};