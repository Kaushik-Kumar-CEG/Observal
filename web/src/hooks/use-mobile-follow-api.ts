// SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { mobileFollow } from "@/lib/api";

export function useApproveFollowWrite() {
  return useMutation({ mutationFn: mobileFollow.approveWrite });
}

export function useFollowConsentState(enabled: boolean) {
  return useQuery({ queryKey: ["mobile-follow", "consent-state"], queryFn: mobileFollow.consentState, enabled, retry: false });
}

export function useAcceptFollowConsent() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: mobileFollow.acceptConsent,
    onSuccess: () => client.invalidateQueries({ queryKey: ["mobile-follow", "consent-state"] }),
  });
}
