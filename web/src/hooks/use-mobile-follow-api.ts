// SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { useMutation } from "@tanstack/react-query";
import { mobileFollow } from "@/lib/api";

export function useApproveFollowWrite() {
  return useMutation({ mutationFn: mobileFollow.approveWrite });
}
