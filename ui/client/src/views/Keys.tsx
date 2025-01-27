// Copyright © 2025 Kaleido, Inc.
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

import { Alert, Box, Breadcrumbs, Fade, IconButton, Link, Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography, useTheme } from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import { t } from "i18next";
import { useContext, useState } from "react";
import { ApplicationContext } from "../contexts/ApplicationContext";
import { fetchKeys } from "../queries/keys";
import { Hash } from "../components/Hash";
import AddBoxIcon from '@mui/icons-material/AddBox';
import NavigateNextIcon from '@mui/icons-material/NavigateNext';
import { getAltModeScrollBarStyle } from "../themes/default";

export const Keys: React.FC = () => {

  const { lastBlockWithTransactions, autoRefreshEnabled } = useContext(ApplicationContext);
  const [parent, setParent] = useState('');
  const theme = useTheme();

  const { data: keys, error, isFetching } = useQuery({
    queryKey: ["keys", autoRefreshEnabled, lastBlockWithTransactions, parent],
    queryFn: () => fetchKeys(parent)
  });

  if (isFetching) {
    return <></>;
  }

  if (error) {
    return <Alert sx={{ margin: '30px' }} severity="error" variant="filled">{error.message}</Alert>
  }


  let breadcrumbContent: JSX.Element[] = [];
  if (parent !== '') {
    const segments = parent.split('.');
    let segmentStack: string[] = [];
    for (const segment of segments) {
      segmentStack.push(segment);
      const target = segmentStack.join('.');
      breadcrumbContent.push(
        <Link underline="none"
          key={segment}
          href={target === parent ? undefined : ''}
          sx={{ textTransform: 'none' }}
          onClick={event => {
            event.preventDefault();
            setParent(target);
          }}>
          {segment === '' ? t('root') : segment}
        </Link>
      )
    }
  }

  return (
    <Fade timeout={600} in={true}>
      <Box
        sx={{
          padding: "30px",
          maxWidth: "1300px",
          marginLeft: "auto",
          marginRight: "auto",
          position: 'relative'
        }}
      >
        <Typography align="center" variant="h5" sx={{ marginBottom: '20px' }}>
          {t("localKeys")}
        </Typography>
        <Breadcrumbs
          separator={<NavigateNextIcon fontSize="small" />}
          sx={{ marginLeft: '10px', marginBottom: '10px' }}>
          <Link underline="none"
            href=""
            sx={{ textTransform: 'none' }}
            onClick={event => { event.preventDefault(); setParent('') }}>
            {t('root')}
          </Link>
          {breadcrumbContent}
        </Breadcrumbs>
        <Box
          sx={{
            paddingRight: '15px',
            height: "calc(100vh - 210px)",
            ...getAltModeScrollBarStyle(theme.palette.mode)
          }}
        >
          <TableContainer component={Paper} >
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell></TableCell>
                  <TableCell>{t('name')}</TableCell>
                  <TableCell>{t('index')}</TableCell>
                  <TableCell>{t('type')}</TableCell>
                  <TableCell>{t('verifier')}</TableCell>
                  <TableCell>{t('wallet')}</TableCell>
                  <TableCell>{t('handle')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {keys?.map(key =>
                  <TableRow key={`${key.wallet}${key.type}${key.path}${key.index}`}>
                    <TableCell>{key.hasChildren &&
                      <IconButton onClick={() => setParent(key.path)}>
                        <AddBoxIcon fontSize="small" />
                      </IconButton>
                    }</TableCell>
                    <TableCell>{key.path}</TableCell>
                    <TableCell>{key.index}</TableCell>
                    <TableCell>{key.type}</TableCell>
                    <TableCell>
                      {key.verifier &&
                        <Hash title={t('verifier')} hash={key.verifier} hideTitle />}
                    </TableCell>
                    <TableCell>{key.wallet}</TableCell>
                    <TableCell>{key.keyHandle}</TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      </Box>
    </Fade>
  );

}
