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

import { Box, CssBaseline } from "@mui/material";
import { createTheme, ThemeProvider } from "@mui/material/styles";
import {
  MutationCache,
  QueryCache,
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Header } from "./components/Header";
import { ApplicationContextProvider } from "./contexts/ApplicationContext";
import { themeOptions } from "./themes/default";
import { Indexer } from "./views/indexer";
import { Registries } from "./views/Registries";
import { Submissions } from "./views/Submissions";

const queryClient = new QueryClient({
  queryCache: new QueryCache({}),
  mutationCache: new MutationCache({}),
});

function App() {
  const theme = createTheme(themeOptions);

  return (
    <>
      <QueryClientProvider client={queryClient}>
        <ApplicationContextProvider>
          <ThemeProvider theme={theme}>
            <CssBaseline />
            <Box
              sx={{
                position: "fixed",
                height: "100vh",
                width: "100vw",
                zIndex: -1,
                backgroundImage: 'url("paladin-icon-light.svg")',
                backgroundRepeat: "no-repeat",
                backgroundSize: "88vh",
                backgroundPosition: "center bottom",
                backgroundAttachment: "fixed",
              }}
            />
            <BrowserRouter>
              <Header />
              <Routes>
                <Route path="/indexer" element={<Indexer />} />
                <Route path="/submissions" element={<Submissions />} />\
                <Route path="/registry" element={<Registries />} />
                <Route path="*" element={<Navigate to="/indexer" replace />} />
              </Routes>
            </BrowserRouter>
          </ThemeProvider>
        </ApplicationContextProvider>
      </QueryClientProvider>
    </>
  );
}

export default App;
