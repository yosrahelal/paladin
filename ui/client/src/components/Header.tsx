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

import { AppBar, Box, Grid2, IconButton, Tab, Tabs, Toolbar, Tooltip, useMediaQuery, useTheme } from "@mui/material";
import { useContext, useState } from "react";
import { useTranslation } from "react-i18next";
import { useLocation, useNavigate } from "react-router-dom";
import Brightness4Icon from '@mui/icons-material/Brightness4';
import { ApplicationContext } from "../contexts/ApplicationContext";


export const Header: React.FC = () => {

  const { colorMode } = useContext(ApplicationContext);
  const { t } = useTranslation();
  const navigate = useNavigate();
  const pathname = useLocation().pathname.toLowerCase();
  const theme = useTheme();
  const lessThanMedium = useMediaQuery(theme.breakpoints.down("md"));

  const getTabFromPath = (path: string) => {
    if (path.startsWith('/ui/indexer')) {
      return 0;
    } else if (path.startsWith('/ui/submissions')) {
      return 1;
    } else if (path.startsWith('/ui/registry')) {
      return 2;
    }
    return 0;
  };

  const [tab, setTab] = useState(getTabFromPath(pathname));

  const handleNavigation = (tab: number) => {
    setTab(tab);
    switch (tab) {
      case 0: navigate('/ui/indexer'); break;
      case 1: navigate('/ui/submissions'); break;
      case 2: navigate('/ui/registry'); break;
    }
  };

  return (
    <>
      <AppBar>
        <Toolbar sx={{ backgroundColor: theme => theme.palette.background.paper }}>
          <Grid2 container alignItems="center" size={{ xs: 12 }}>
            <Grid2 size={{ xs: 12, sm: 12, md: 4 }} textAlign="center">
              <img src={theme.palette.mode === 'dark' ?
                '/ui/paladin-title-dark.svg' : '/ui/paladin-title-light.svg'
              } style={{ marginTop: '7px' }} />
            </Grid2>
            <Grid2 size={{ xs: 12, sm: 12, md: 4 }} alignContent="center">
              <Tabs value={tab} onChange={(_event, value) => handleNavigation(value)} centered>
                <Tab sx={{ textTransform: 'none' }} label={t('indexer')} />
                <Tab sx={{ textTransform: 'none' }} label={t('submissions')} />
                <Tab sx={{ textTransform: 'none' }} label={t('registry')} />
              </Tabs>
            </Grid2>
            <Grid2 size={{ xs: 12, sm: 12, md: 4 }} textAlign="center">
              <Tooltip arrow title={t('switchThemeMode')}>
                <IconButton onClick={() => colorMode.toggleColorMode()}>
                  <Brightness4Icon />
                </IconButton>
              </Tooltip>
            </Grid2>
          </Grid2>
        </Toolbar>
      </AppBar>
      <Box sx={{ height: theme => lessThanMedium? '134px' :
         theme.mixins.toolbar }} />
    </>
  );

};