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

import { ThemeOptions } from '@mui/material';

export const darkThemeOptions: ThemeOptions = {

  palette: {
    mode: 'dark',
    primary: {
      main: '#20dfdf',
      dark: '#6D6D6D'
    },
    background: {
      default: 'black',
      paper: 'black',
    }
  }

};

export const lightThemeOptions: ThemeOptions = {

  palette: {
    mode: 'light',
    primary: {
      main: '#107070',
      dark: '#6D6D6D'
    },
    background: {
      default: '#F0F0F0',
      paper: '#FFFFFF',
    }
  }

};