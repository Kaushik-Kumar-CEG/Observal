// SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { auth } from "@/lib/api";

export function useDevicePreview(code: string | null) {
  return useQuery({
    queryKey: ["device-preview", code],
    queryFn: () => auth.devicePreview(code!),
    enabled: code !== null,
    retry: false,
    staleTime: 0,
    gcTime: 0,
  });
}
