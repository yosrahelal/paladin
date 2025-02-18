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

import { Alert, Box, LinearProgress, Typography, useTheme } from "@mui/material";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { fetchRegistryEntries } from "../queries/registry";
import { RegistryEntry } from "./RegistryEntry";
import { IRegistryEntry } from "../interfaces";
import { getAltModeScrollBarStyle } from "../themes/default";
import InfiniteScroll from "react-infinite-scroll-component";
import { useTranslation } from "react-i18next";

type Props = {
  registryName: string;
};

export const Registry: React.FC<Props> = ({ registryName }) => {

  const theme = useTheme();
  const { t } = useTranslation();

  const { data: registryEntries, fetchNextPage, hasNextPage, error } = useInfiniteQuery({
    queryKey: ["registryEntries"],
    queryFn: ({ pageParam }) => fetchRegistryEntries(registryName, pageParam),
    initialPageParam: undefined as IRegistryEntry | undefined,
    getNextPageParam: (lastPage) => { return lastPage.length > 0 ? lastPage[lastPage.length - 1] : undefined },
  });

  if (error) {
    return <Alert sx={{ margin: '30px' }} severity="error" variant="filled">{error.message}</Alert>
  }

  if (registryEntries?.pages === undefined) {
    return <></>;
  }

  return (
    <Box
      id="scrollableDivRegistryEntries"
      sx={{
        paddingRight: "15px",
        height: "calc(100vh - 250px)",
        ...getAltModeScrollBarStyle(theme.palette.mode)
      }}
    >
      <InfiniteScroll
        scrollableTarget="scrollableDivRegistryEntries"
        dataLength={registryEntries.pages.length}
        next={() => fetchNextPage()}
        hasMore={hasNextPage}
        loader={<LinearProgress />}
      >
        {registryEntries.pages.map(registryEntriesArray =>
          registryEntriesArray.map(registryEntry => (
            <RegistryEntry
              key={registryEntry.name}
              registryEntry={registryEntry}
            />
          ))
        )}
      </InfiniteScroll>
      {registryEntries.pages.length === 1 && registryEntries.pages[0].length === 0 &&
        <Typography color="textSecondary" align="center" variant="h6" sx={{ marginTop: '40px' }}>{t('noPendingTransactions')}</Typography>}
    </Box>
  );
};
