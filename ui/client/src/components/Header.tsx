// Copyright © 2026 Kaleido, Inc.
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

import MenuIcon from '@mui/icons-material/Menu';
import RefreshIcon from '@mui/icons-material/Refresh';
import {
  AppBar,
  Box,
  Button,
  ButtonBase,
  Grid2,
  IconButton,
  Tab,
  Tabs,
  Toolbar,
  useMediaQuery,
  useTheme,
} from '@mui/material';
import { useContext, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import logoDark from '../../public/paladin-title-dark.svg';
import logoLight from '../../public/paladin-title-light.svg';
import { ApplicationContext } from '../contexts/ApplicationContext';
import { SettingsMenu } from '../menus/Settings';
import { AppRoutes } from '../routes';
import { customNavigate } from '../utils';

enum HeaderTab {
  Transactions = 0,
  Submissions = 1,
  Keys = 2,
  Registry = 3,
  Domains = 4,
  PrivacyGroups = 5
}

export const Header: React.FC = () => {
  const { refreshRequired, refresh } = useContext(ApplicationContext);
  const { t } = useTranslation();
  const navigate = useNavigate();
  const pathname = useLocation().pathname.toLowerCase();
  const theme = useTheme();
  const lessThanLarge = useMediaQuery(theme.breakpoints.down('lg'));
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [searchParams] = useSearchParams();

  const getTabFromPath = (path: string) => {
    switch (searchParams.get('back')) {
      case 'transactions': return HeaderTab.Transactions;
      case 'submissions': return HeaderTab.Submissions;
      case 'domains': return HeaderTab.Domains;
    }
    if (path.startsWith(AppRoutes.Transactions)) {
      return HeaderTab.Transactions;
    } else if (path.startsWith(AppRoutes.Submissions)) {
      return HeaderTab.Submissions;
    } else if (path.startsWith(AppRoutes.Keys)) {
      return HeaderTab.Keys;
    } else if (path.startsWith(AppRoutes.Registry)) {
      return HeaderTab.Registry;
    } else if (path.startsWith(AppRoutes.Domains)) {
      return HeaderTab.Domains;
    } else if (path.startsWith(AppRoutes.PrivactGroups)) {
      return HeaderTab.PrivacyGroups;
    }
    return HeaderTab.Transactions;
  };

  const [tab, setTab] = useState(getTabFromPath(pathname));

  return (
    <>
      <AppBar>
        <Toolbar
          sx={{ backgroundColor: (theme) => theme.palette.background.paper }}
        >
          <Box
            sx={{
              width: '100%',
              maxWidth: '1270px',
              marginLeft: 'auto',
              marginRight: 'auto',
            }}
          >
            <Grid2 container alignItems="center">
              <Grid2
                size={{ xs: 12, sm: 12, md: 12, lg: 2 }}
                textAlign={lessThanLarge ? 'center' : 'left'}
              >
                <ButtonBase
                  onClick={() => window.location.href = '/ui'}>
                  <img
                    src={theme.palette.mode === 'dark' ? logoDark : logoLight}
                    style={{ marginTop: '7px' }}
                  />
                </ButtonBase>
              </Grid2>
              <Grid2 size={{ xs: 12, sm: 12, md: 12, lg: 8 }} alignContent="center">
                <Tabs
                  TabIndicatorProps={{ style: { height: '4px' } }}
                  value={tab}
                  onChange={(event: any, value) => {
                    if (!(event.metaKey || event.ctrlKey || event.button === 1)) {
                      setTab(value);
                    }
                  }}
                  centered
                >
                  <Tab sx={{ minWidth: '120px' }} label={t('transactions')} onClick={event => customNavigate(AppRoutes.Transactions, event, navigate)} />
                  <Tab sx={{ minWidth: '120px' }} label={t('submissions')} onClick={event => customNavigate(AppRoutes.Submissions, event, navigate)} />
                  <Tab sx={{ minWidth: '120px' }} label={t('localKeys')} onClick={event => customNavigate(AppRoutes.Keys, event, navigate)} />
                  <Tab sx={{ minWidth: '120px' }} label={t('registry')} onClick={event => customNavigate(AppRoutes.Registry, event, navigate)} />
                  <Tab sx={{ minWidth: '120px' }} label={t('domains')} onClick={event => customNavigate(AppRoutes.Domains, event, navigate)} />
                  <Tab sx={{ minWidth: '120px' }} label={t('privacyGroups')} onClick={event => customNavigate(AppRoutes.PrivactGroups, event, navigate)} />
                </Tabs>
              </Grid2>
              <Grid2 size={{ xs: 12, sm: 12, md: 12, lg: 2 }}>
                <Grid2
                  container
                  justifyContent={lessThanLarge ? 'center' : 'right'}
                  spacing={1}
                  alignItems="center"
                  sx={{ padding: lessThanLarge ? '20px' : undefined }}
                >
                  {refreshRequired && (
                    <Grid2>
                      <Button
                        size="small"
                        startIcon={<RefreshIcon />}
                        variant="outlined"
                        sx={{ borderRadius: '20px' }}
                        onClick={() => refresh()}
                      >
                        {t('newData')}
                      </Button>
                    </Grid2>
                  )}
                  <Grid2>
                    <IconButton
                      onClick={(event) => setAnchorEl(event.currentTarget)}
                    >
                      <MenuIcon />
                    </IconButton>
                  </Grid2>
                </Grid2>
              </Grid2>
            </Grid2>
          </Box>
        </Toolbar>
      </AppBar>
      <Box
        sx={{
          height: (theme) => (lessThanLarge ? '190px' : theme.mixins.toolbar),
        }}
      />
      <SettingsMenu anchorEl={anchorEl} setAnchorEl={setAnchorEl} />
    </>
  );
};
