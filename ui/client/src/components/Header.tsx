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

import { AppBar, Box, Toolbar, Typography } from "@mui/material";
import { useTranslation } from "react-i18next";
import HandymanIcon from '@mui/icons-material/Handyman';

export const Header: React.FC = () => {

  const { t } = useTranslation();

  return (
    <>
      <AppBar>
        <Toolbar sx={{ justifyContent: 'center'}}>
          <HandymanIcon sx={{ marginRight: '10px'}} />
          <Typography variant="h6">{t('paladinDebugToolkit')}</Typography>
        </Toolbar>
      </AppBar>
      <Box sx={{ height: theme => theme.mixins.toolbar }} />
    </>
  );

};