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

export const Transactions: React.FC = () => {
  const { lastBlockWithTransactions } = useContext(ApplicationContext);

  const { data: transactions } = useQuery({
    queryKey: ["transactions", lastBlockWithTransactions],
    queryFn: () => fetchIndexedTransactions(),
  });

  const { data: transactionReceipts } = useQuery({
    queryKey: ["transactionReceipts", transactions],
    queryFn: () => fetchTransactionReceipts(transactions ?? []),
    enabled: transactions !== undefined,
  });

  const { data: paladinTransactions } = useQuery({
    queryKey: ["paladinTransactions", transactionReceipts],
    queryFn: () => fetchPaladinTransactions(transactionReceipts ?? []),
    enabled: transactionReceipts !== undefined,
  });

  if (paladinTransactions === undefined) {
    return <></>;
  }

  return (
    <>
      <Typography align="center" sx={{ fontSize: "24px", fontWeight: 500 }}>
        {t("transactions")}
      </Typography>
      <Box
        sx={{
          height: "calc(100vh - 162px)",
          overflow: "scroll",
          padding: "20px",
        }}
      >
        {transactions?.map((transaction) => (
          <Transaction
            key={transaction.hash}
            transaction={transaction}
            transactionReceipt={transactionReceipts?.find(
              (transactionReceipt) =>
                transactionReceipt.transactionHash === transaction.hash
            )}
            paladinTransaction={paladinTransactions?.find(
              (paladinTransaction) =>
                paladinTransaction.id ===
                transactionReceipts?.find(
                  (transactionReceipt) =>
                    transactionReceipt.transactionHash === transaction.hash
                )?.id
            )}
          />
        ))}
      </Box>
    </>
  );
};
