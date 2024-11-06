import { useQuery } from "@tanstack/react-query";
import { createContext } from "react";
import { constants } from "../components/config";
import { ErrorDialog } from "../dialogs/Error";
import { fetchLatestBlockWithTxs } from "../queries/blocks";

interface IApplicationContext {
  colorMode: {
    toggleColorMode: () => void;
  };
  lastBlockWithTransactions: number;
}

export const ApplicationContext = createContext({} as IApplicationContext);

interface Props {
  colorMode: {
    toggleColorMode: () => void;
  };
  children: JSX.Element;
}

export const ApplicationContextProvider = ({ children, colorMode }: Props) => {

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
    retry: true
  });

  return (
    <ApplicationContext.Provider
      value={{ lastBlockWithTransactions: lastBlockWithTransactions ?? 0, colorMode }}
    >
      {children}
      <ErrorDialog dialogOpen={!!error} message={error?.message ?? ""} />
    </ApplicationContext.Provider>
  );
};
