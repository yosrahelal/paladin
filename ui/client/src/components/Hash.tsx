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

import { Button } from "@mui/material";
import { useState } from "react";
import { HashDialog } from "../dialogs/Hash";

const MAX_LENGTH_WITHOUT_COLLAPSE = 16;

type Props = {
  title: string
  hash: string
}

export const Hash: React.FC<Props> = ({ title, hash }) => {

  const [hashDialogOpen, setHashDialogOpen] = useState(false);

  const getHash = (value: string) => {
    if(value.length < MAX_LENGTH_WITHOUT_COLLAPSE) {
      return hash;
    }
    return `${value.substring(0, 5)}...${value.substring(value.length - 3)}`
  };

  return (
    <>
      <Button disableElevation onClick={() => setHashDialogOpen(true)} fullWidth variant="contained" sx={{ paddingTop: 0, paddingBottom: 0, textTransform: 'none', fontWeight: '400'}} size="small">
        {`${title} | ${getHash(hash)}`}
      </Button>
      <HashDialog dialogOpen={hashDialogOpen} setDialogOpen={setHashDialogOpen} title={title} hash={hash} />
    </>
  );

};