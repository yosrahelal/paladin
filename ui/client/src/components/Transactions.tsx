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

import { Alert, Box, Typography, useTheme } from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import { t } from "i18next";
import { useContext } from "react";
import { ApplicationContext } from "../contexts/ApplicationContext";
import {
  fetchIndexedTransactions,
  fetchPaladinTransactions,
  fetchTransactionReceipts,
} from "../queries/transactions";
import { Transaction } from "./Transaction";
import { altLightModeScrollbarStyle, altDarkModeScrollbarStyle } from "../themes/default";


export const Transactions: React.FC = () => {
  const { lastBlockWithTransactions } = useContext(ApplicationContext);
  
  const theme = useTheme();
  const addedStyle = theme.palette.mode === 'light'? altLightModeScrollbarStyle : altDarkModeScrollbarStyle;

  const { data: transactions, error: transactionError, isRefetching: transactionFetching } = useQuery({
    queryKey: ["transactions", lastBlockWithTransactions],
    queryFn: () => fetchIndexedTransactions(),
  });

  const { data: transactionReceipts, error: receiptError, isFetching: receiptFetching } = useQuery({
    queryKey: ["transactionReceipts", transactions],
    queryFn: () => fetchTransactionReceipts(transactions ?? []),
    enabled: transactions !== undefined,
  });

  const { data: paladinTransactions, error: paladinTransactionError, isFetching: paladinTransactionFetching } = useQuery({
    queryKey: ["paladinTransactions", transactionReceipts],
    queryFn: () => fetchPaladinTransactions(transactionReceipts ?? []),
    enabled: transactionReceipts !== undefined,
  });

  if(transactionFetching || receiptFetching || paladinTransactionFetching) {
    return <></>;
  }

  if (transactionError || receiptError || paladinTransactionError) {
    return <Alert sx={{ margin: '30px' }} severity="error" variant="filled">{transactionError?.message ?? receiptError?.message ?? paladinTransactionError?.message}</Alert>
  }

  return (
    <>
      <Typography align="center" variant="h5" sx={{ marginBottom: '20px' }}>
        {t("transactions")}
      </Typography>
      <Box
        sx={{
          height: "calc(100vh - 170px)",
          paddingRight: "15px",
          ...addedStyle
        }}
      >
        {transactions?.map((transaction) => (
          <Transaction
            key={transaction.hash}
            transaction={transaction}
            transactionReceipts={transactionReceipts?.filter(
              (transactionReceipt) =>
                transactionReceipt.transactionHash === transaction.hash
            )}
            paladinTransactions={paladinTransactions?.filter(
              (paladinTransaction) =>
                transactionReceipts?.filter(
                  (transactionReceipt) =>
                    transactionReceipt.transactionHash === transaction.hash
                ).map(transactionReceipt => (transactionReceipt.id)).includes(paladinTransaction.id)
            )}
          />
        ))}
      </Box>
    </>
  );
};
