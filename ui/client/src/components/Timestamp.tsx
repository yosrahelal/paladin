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

import { ButtonBase, Typography } from "@mui/material";
import { useState } from "react";
import { TimestampDialog } from "../dialogs/Timestamp";

type Props = {
  date: Date
};

export const Timestamp: React.FC<Props> = ({ date }) => {

  const [timestampDialogOpen, setTimestampDialogOpen] = useState(false);

  return (
    <>
      <ButtonBase onClick={() => setTimestampDialogOpen(true)}>
        <Typography variant="h6" color="primary">
          {`${date.getFullYear()}-${date.getMonth() + 1}-${date.getDate()} ${date.getHours()}:${date.getMinutes()}:${date.getSeconds()}`}
        </Typography>
      </ButtonBase>
      <TimestampDialog dialogOpen={timestampDialogOpen} setDialogOpen={setTimestampDialogOpen} date={date} />
    </>);
}