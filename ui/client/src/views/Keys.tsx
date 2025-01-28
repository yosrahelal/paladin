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

import { Alert, Box, Breadcrumbs, Fade, IconButton, Link, Paper, Table, TableBody, TableCell, TableContainer, TableHead, TablePagination, TableRow, TableSortLabel, Tooltip, Typography } from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import { t } from "i18next";
import { useEffect, useState } from "react";
import { fetchKeys } from "../queries/keys";
import { Hash } from "../components/Hash";
import FolderOpenIcon from '@mui/icons-material/FolderOpen';
import NavigateNextIcon from '@mui/icons-material/NavigateNext';
import { IKeyEntry } from "../interfaces";
import { useSearchParams } from "react-router-dom";
import { Captions, Signature } from "lucide-react";
import { constants } from "../components/config";

export const Keys: React.FC = () => {

  const [searchParams, setSearchParams] = useSearchParams();
  const [refEntries, setRefEntries] = useState<IKeyEntry[]>([]);
  const [page, setPage] = useState(0);
  const [count, setCount] = useState(-1);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [parent, setParent] = useState(searchParams.get('path') ?? '');
  const [sortBy, setSortBy] = useState(window.localStorage.getItem(constants.KEY_SORT_BY_STORAGE_KEY) ?? 'index');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>(
    window.localStorage.getItem(constants.KEY_SORT_ORDER_STORAGE_KEY) as 'asc' | 'desc' ?? 'asc');

  const { data: keys, error } = useQuery({
    queryKey: ["keys", parent, sortBy, sortOrder, refEntries, rowsPerPage],
    queryFn: () => fetchKeys(parent, rowsPerPage, sortBy, sortOrder, refEntries[refEntries.length - 1])
  });

  useEffect(() => {
    if (count !== -1 && (page * rowsPerPage === count)) {
      handleChangePage(null, page - 1);
    }
  }, [count, rowsPerPage, page]);

  useEffect(() => {
    if (keys !== undefined && count === -1) {
      if (keys.length < rowsPerPage) {
        setCount(rowsPerPage * page + keys.length);
      }
    }
  }, [keys, rowsPerPage, page]);

  useEffect(() => {
    setCount(-1);
    setPage(0);
    setRefEntries([]);
  }, [parent]);

  useEffect(() => {
    if (parent === '') {
      setSearchParams({});
    } else {
      setSearchParams({ path: parent });
    }
  }, [parent, page]);

  if (error) {
    return <Alert sx={{ margin: '30px' }} severity="error" variant="filled">{error.message}</Alert>
  }

  if (keys === undefined) {
    return <></>;
  }

  const handleSortChange = (column: string) => {
    if (column === sortBy) {
      const order = sortOrder === 'asc' ? 'desc' : 'asc';
      setSortOrder(order);
      window.localStorage.setItem(constants.KEY_SORT_ORDER_STORAGE_KEY, order);
    } else {
      window.localStorage.setItem(constants.KEY_SORT_BY_STORAGE_KEY, column);
      if (sortOrder !== 'asc') {
        window.localStorage.setItem(constants.KEY_SORT_ORDER_STORAGE_KEY, 'asc');
        setSortOrder('asc');
      }
      setSortBy(column);
    }
  };

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

  const getEthAddress = (key: IKeyEntry) => {
    const entry = key.verifiers?.find(entry => entry.type === 'eth_address');
    if (entry !== undefined) {
      return <Hash
        Icon={<Captions size="18px" />}
        title={entry.algorithm}
        hash={entry.verifier}
        hideTitle />
    }
    return '--';
  };

  const getOtherVerifiers = (key: IKeyEntry) => {
    if (key.verifiers !== null) {
      const entries = key.verifiers.filter(entry => entry.type !== 'eth_address');
      if (entries.length === 1) {
        return <Hash
          Icon={<Signature size="18px" />}
          title={entries[0].algorithm}
          hash={entries[0].verifier}
          hideTitle />
      } else if (entries.length > 1) {
        // TODO: once we have more than 2, we should have an experience for listing
        //       an arbitrary number of verifiers
      }
    }
    return '--';
  };

  const handleChangePage = (
    _event: React.MouseEvent<HTMLButtonElement> | null,
    newPage: number
  ) => {
    if (newPage === 0) {
      setRefEntries([]);
    } else if (newPage > page) {
      refEntries.push(keys[keys.length - 1]);
    } else {
      refEntries.pop();
    }
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (
    event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const headerDivider = <Box sx={{
    height: '30px',
    width: '1px',
    border: theme => `solid 1px ${theme.palette.divider}`,
    position: 'absolute',
    top: '14px',
    left: '2px'
  }} />;


  return (
    <Fade timeout={300} in={true}>
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

        <TableContainer component={Paper} >
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>
                </TableCell>
                <TableCell sx={{ position: 'relative' }}>
                  <TableSortLabel
                    active={sortBy === 'path'}
                    direction={sortOrder}
                    onClick={() => handleSortChange('path')}
                  >
                    {t('name')}
                  </TableSortLabel>
                  {headerDivider}
                </TableCell>
                <TableCell sx={{ position: 'relative' }}>
                  <TableSortLabel
                    active={sortBy === 'index'}
                    direction={sortOrder}
                    onClick={() => handleSortChange('index')}
                  >
                    {t('index')}
                  </TableSortLabel>
                  {headerDivider}
                </TableCell>
                <TableCell sx={{ position: 'relative' }} width={1}>{t('address')}{headerDivider}</TableCell>
                <TableCell width={1} sx={{ whiteSpace: 'nowrap', position: 'relative' }}>{t('otherVerifiers')}{headerDivider}</TableCell>
                <TableCell sx={{ position: 'relative' }}>{t('wallet')}{headerDivider}</TableCell>
                <TableCell width={1} sx={{ position: 'relative' }}>{t('handle')}{headerDivider}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {keys.map(key =>
                <TableRow sx={{ height: '70px' }} key={`${key.wallet}${key.type}${key.path}${key.index}`}>
                  <TableCell>{key.hasChildren &&
                    <Tooltip arrow title={t('openFolder')}>
                      <IconButton onClick={() => setParent(key.path)}>
                        <FolderOpenIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  }</TableCell>
                  <TableCell>{key.path}</TableCell>
                  <TableCell>{key.index}</TableCell>
                  <TableCell>
                    {getEthAddress(key)}
                  </TableCell>
                  <TableCell>
                    {getOtherVerifiers(key)}
                  </TableCell>
                  <TableCell>{key.wallet.length > 0 ? key.wallet : '--'}</TableCell>
                  <TableCell>{key.keyHandle.length > 0 ?
                    <Hash hash={key.keyHandle} title={t('handle')} hideTitle secondary />
                    : '--'}</TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
          <TablePagination
            slotProps={{
              actions: {
                lastButton: {
                  disabled: true
                }
              }
            }}
            component="div"
            showFirstButton
            showLastButton
            count={count}
            page={page}
            onPageChange={handleChangePage}
            rowsPerPage={rowsPerPage}
            onRowsPerPageChange={handleChangeRowsPerPage}
          />
        </TableContainer>
      </Box>
    </Fade>
  );

}
