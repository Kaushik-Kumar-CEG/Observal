// SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

export type FollowWriteApprovalRequest = {
  user_code: string;
  approve: true;
};

export type FollowWriteApprovalResponse = {
  state: "approved";
};

export type FollowConsentState = {
  state: "available" | "consent_required" | "disabled" | "withdrawal_pending";
  owner_generation: number;
};

export type FollowConsentRequest = {
  consent: true;
  consent_id: string;
  owner_generation: number;
};

export type FollowConsentResponse = {
  state: string;
  owner_generation: number;
};
