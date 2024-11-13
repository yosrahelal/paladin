import { useQuery } from "@tanstack/react-query";
import { createContext, Dispatch, SetStateAction, useEffect, useState } from "react";
import { constants } from "../components/config";
import { ErrorDialog } from "../dialogs/Error";
import { fetchLatestBlockWithTxs } from "../queries/blocks";

interface IApplicationContext {
  colorMode: {
    toggleColorMode: () => void;
  };
  lastBlockWithTransactions: number;
  autoRefreshEnabled: boolean;
  setAutoRefreshEnabled: Dispatch<SetStateAction<boolean>>;
  refreshRequired: boolean;
  refresh: () => void;
}

export const ApplicationContext = createContext({} as IApplicationContext);

interface Props {
  colorMode: {
    toggleColorMode: () => void;
  };
  children: JSX.Element;
}

export const ApplicationContextProvider = ({ children, colorMode }: Props) => {

  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(true);
  const [lastBlockWithTransactions, setLastBlockWithTransactions] = useState(0);
  const [refreshRequired, setRefreshRequired] = useState(false);

  const { data: actualLastBlockWithTransactions, error } = useQuery({
    queryKey: ["lastBlockWithTransactions"],
    queryFn: () =>
      fetchLatestBlockWithTxs().then((res) => {
        if (res.length > 0) {
          return res[0].blockNumber;
        }
        return 0;
      }),
    refetchInterval: constants.UPDATE_FREQUENCY_MILLISECONDS,
    retry: false
  });


  useEffect(() => {
    if(actualLastBlockWithTransactions !== undefined
      && actualLastBlockWithTransactions > lastBlockWithTransactions) {
        if(autoRefreshEnabled) {
          setLastBlockWithTransactions(actualLastBlockWithTransactions);
        } else {
          setRefreshRequired(true);
        }
    }
  }, [actualLastBlockWithTransactions, lastBlockWithTransactions, setLastBlockWithTransactions]);

  const refresh = () => {
    if(actualLastBlockWithTransactions !== undefined) {
      setLastBlockWithTransactions(actualLastBlockWithTransactions);
    }
    setRefreshRequired(false);
  };

  return (
    <ApplicationContext.Provider
      value={{
        lastBlockWithTransactions: lastBlockWithTransactions, colorMode,
        autoRefreshEnabled, setAutoRefreshEnabled, refreshRequired, refresh
      }}
    >
      {children}
      <ErrorDialog dialogOpen={!!error} message={error?.message ?? ""} />
    </ApplicationContext.Provider>
  );
};
