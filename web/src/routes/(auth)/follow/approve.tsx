// SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { createFileRoute } from "@tanstack/react-router";
import { lazy, Suspense } from "react";
import { Toaster } from "@/components/ui/sonner";

const FollowApprovePage = lazy(() => import("@/pages/follow-approve"));

function FollowApproveRoute() {
  return (
    <div className="min-h-dvh bg-background">
      <Suspense fallback={<div className="flex h-screen w-full items-center justify-center" />}>
        <FollowApprovePage />
      </Suspense>
      <Toaster visibleToasts={1} />
    </div>
  );
}

export const Route = createFileRoute("/(auth)/follow/approve")({ component: FollowApproveRoute });
