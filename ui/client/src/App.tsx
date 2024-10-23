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

import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { ApplicationContext } from "./Context"
import { createTheme, ThemeProvider } from "@mui/material/styles";
import { themeOptions } from "./themes/default";
import { Header } from "./components/Header";
import { Indexer } from "./views/indexer";
import { Box, CssBaseline } from "@mui/material";
import { useEffect, useState } from "react";
import { constants, getLatestBlockWithTransactions } from "./utils";
import { Registries } from "./views/Registries";
import { ErrorDialog } from "./dialogs/Error";
import { Submissions } from "./views/Submissions";

function App() {

  const theme = createTheme(themeOptions);
  const [lastBlockWithTransactions, setLastBlockWithTransactions] = useState(0);
  const [errorMessage, setErrorMessage] = useState<string>();

  useEffect(() => {
    const intervalId = setInterval(() => {
      getLatestBlockWithTransactions().then(data => {
        setErrorMessage(undefined);
        if (data !== lastBlockWithTransactions) {
          setLastBlockWithTransactions(data)
        }
      }).catch((err: any) => {
        setErrorMessage(err.message);
      })
    }, constants.UPDATE_FREQUENCY_MILLISECONDS);
    return () => clearInterval(intervalId);
  }, []);

  return (
    <ApplicationContext.Provider value={{ lastBlockWithTransactions, errorMessage }}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Box sx={{
          position: 'fixed', height: '100vh', width: '100vw', zIndex: -1,
          backgroundImage: 'url("paladin-icon-light.svg")', backgroundRepeat: 'no-repeat',
          backgroundSize: '88vh', backgroundPosition: 'center bottom', backgroundAttachment: 'fixed'
        }} />
        <BrowserRouter>
          <Header />
          <Routes>
            <Route path="/indexer" element={<Indexer />} />
            <Route path="/submissions" element={<Submissions />} />\
            <Route path="/registry" element={<Registries />} />
            <Route path="*" element={<Navigate to="/indexer" replace />} />
          </Routes>
        </BrowserRouter>
        <ErrorDialog dialogOpen={errorMessage !== undefined} message={errorMessage ?? ''} />
      </ThemeProvider>
    </ApplicationContext.Provider>
  )
}

export default App
