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

import { useContext, useEffect, useState } from "react";
import { ApplicationContext } from "../Context";
import { constants } from "../utils";
import { IPendingTransaction } from "../interfaces";
import { Box, Fade, Paper, Typography } from "@mui/material";
import { t } from "i18next";
import { PendingTransaction } from "../components/PendingTransaction";

export const PendingTransactions: React.FC = () => {

  const { lastBlockWithTransactions } = useContext(ApplicationContext);
  const [loading, setLoading] = useState(true);
  const [pendingTransactions, setPendingTransactions] = useState<IPendingTransaction[]>([]);

  useEffect(() => {
    let requestPayload = {
      jsonrpc: '2.0',
      id: Date.now(),
      method: 'ptx_queryPendingTransactions',
      params: [{ limit: constants.PENDING_TRANSACTIONS_QUERY_LIMIT, sort: ['created DESC'] }, true]
    };
    fetch('/json-rpc', {
      method: 'post',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestPayload)
    }).then(async response => {
      setPendingTransactions((await response.json()).result);
    }).finally(() => setLoading(false));
  }, [lastBlockWithTransactions]);

  if (loading) {
    return <></>;
  }

  return (
    <Fade timeout={800} in={true}>
      <Box sx={{ padding: '20px', maxWidth: '1200px', marginLeft: 'auto', marginRight: 'auto' }}>
        <Paper sx={{
          padding: '10px', paddingTop: '12px', backgroundColor: 'rgba(255, 255, 255, .65)',
        }}>
          <Typography align="center" sx={{ fontSize: '24px', fontWeight: 500 }}>{t('pendingTransactions')}</Typography>
          <Box sx={{ padding: '20px', overflow: 'scroll', height: 'calc(100vh - 162px)' }}>
            {pendingTransactions.map(pendingTransaction => <PendingTransaction key={pendingTransaction.id} pendingTransaction={pendingTransaction} />)}
          </Box>
        </Paper>
      </Box>
    </Fade>
  );

}