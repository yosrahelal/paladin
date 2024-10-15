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

import { Box, Typography } from "@mui/material";
import { t } from "i18next";
import { useContext, useEffect, useState } from "react";
import { ITransaction } from "../interfaces";
import { Transaction } from "./Transaction";
import { ApplicationContext } from "../Context";

export const Transactions: React.FC = () => {

  const { lastBlockWithTransactions } = useContext(ApplicationContext);
  const [transactions, setTransactions] = useState<ITransaction[]>();

  useEffect(() => {
    let requestPayload = {
      jsonrpc: '2.0',
      id: Date.now(),
      method: 'bidx_queryIndexedTransactions',
      params: [{ limit: 100, sort: ['blockNumber DESC', 'transactionIndex DESC'] }]
    };
    fetch('/json-rpc', {
      method: 'post',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestPayload)
    }).then(async response => {
      setTransactions((await response.json()).result);
    });
  }, [lastBlockWithTransactions]);

  return (
    <>
      <Typography align="center" sx={{ fontSize: '24px', fontWeight: 500 }}>{t('transactions')}</Typography>
      <Box sx={{  height: 'calc(100vh - 162px)', overflow: 'scroll', padding: '20px' }}>
        {transactions?.map(transaction =>
          <Transaction key={transaction.hash} transaction={transaction} />
        )}
      </Box>
    </>
  );

}