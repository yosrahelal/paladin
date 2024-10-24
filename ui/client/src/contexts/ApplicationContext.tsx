import { useQuery } from "@tanstack/react-query";
import { createContext } from "react";
import { constants } from "../components/config";
import { ErrorDialog } from "../dialogs/Error";
import { fetchLatestBlockWithTxs } from "../queries/blocks";

interface IApplicationContext {
  lastBlockWithTransactions: number;
}

export const ApplicationContext = createContext({} as IApplicationContext);

interface Props {
  children: JSX.Element;
}

export const ApplicationContextProvider = ({ children }: Props) => {
  const { data: lastBlockWithTransactions, error } = useQuery({
    queryKey: ["lastBlockWithTransactions"],
    queryFn: () =>
      fetchLatestBlockWithTxs().then((res) => {
        if (res.length > 0) {
          return res[0].blockNumber;
        }
        return 0;
      }),
    refetchInterval: constants.UPDATE_FREQUENCY_MILLISECONDS,
    retry: (failureCount) => {
      return failureCount < 1;
    },
  });

  return (
    <ApplicationContext.Provider
      value={{ lastBlockWithTransactions: lastBlockWithTransactions ?? 0 }}
    >
      {children}
      <ErrorDialog dialogOpen={!!error} message={error?.message ?? ""} />
    </ApplicationContext.Provider>
  );
};
