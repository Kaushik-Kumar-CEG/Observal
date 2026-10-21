// SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

export type FollowWriteApprovalRequest = {
  user_code: string;
  approve: true;
};

export type FollowWriteApprovalResponse = {
  state: "approved";
};
