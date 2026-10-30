// SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { useLayoutEffect, useState } from "react";
import { useRouter } from "@tanstack/react-router";
import { AlertCircle, CheckCircle2, Loader2 } from "lucide-react";
import { clearSession } from "@/lib/api";
import { useApproveFollowWrite } from "@/hooks/use-api";
import { useWebsiteSessionGuard } from "@/hooks/use-auth";
import { useDeploymentConfig } from "@/hooks/use-deployment-config";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export default function FollowApprovePage() {
  const router = useRouter();
  const { brandingAppName, brandingLogo, brandingWordmark } = useDeploymentConfig();
  const approval = useApproveFollowWrite();
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [needsLogin, setNeedsLogin] = useState(false);
  const ready = useWebsiteSessionGuard("/follow/approve");

  // Keep the one-device code only in this form. Never put it in login's `next`,
  // router history, storage, toast messages or error reporting.
  useLayoutEffect(() => {
    const url = new URL(window.location.href);
    const prefill = url.searchParams.get("code");
    if (prefill) setCode(prefill);
    if (url.search) {
      window.history.replaceState(window.history.state, "", url.pathname + url.hash);
    }
  }, []);

  function signInAgain() {
    clearSession();
    router.navigate({ to: "/login", search: { next: "/follow/approve" }, replace: true });
  }

  async function handleSubmit(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    // Unlike the CLI device code, follow challenge codes are case-sensitive.
    const userCode = code.trim();
    if (!/^[A-Za-z0-9_-]{20,32}$/.test(userCode)) {
      setError("Enter the complete code shown on your phone (20–32 characters). Request a new code if it expired.");
      return;
    }
    setError("");
    setNeedsLogin(false);
    try {
      await approval.mutateAsync({ user_code: userCode, approve: true });
      setCode("");
    } catch (cause) {
      const status = (cause as Error & { status?: number }).status;
      if (status === 401) {
        setNeedsLogin(true);
        setError("Your website session expired. Sign in using your usual method, then request a new phone code.");
      } else if (status === 400 || status === 409) {
        setError("This phone code was rejected or expired. Check the account and request a new code on your phone.");
      } else if (status === 403) {
        // A spent browser-action proof or unavailable consent is not a reason
        // to throw away a still-valid password or SSO website session.
        setError("Approval was not recorded. This action is restricted or account Following is unavailable. Check account state before requesting a new phone code.");
      } else {
        setError("Approval could not be completed. Check your connection and try again, or request a new code on your phone.");
      }
    }
  }

  if (!ready) return null;

  return (
    <div className="flex min-h-dvh items-center justify-center bg-surface-sunken p-6">
      <div className="w-full max-w-md">
        <div className="rounded-lg border bg-card shadow-sm">
          <div className="flex flex-col items-center gap-2 border-b px-8 pb-6 pt-8 animate-in">
            <img loading="lazy" src={brandingLogo || "/observal-logo.svg"} alt="" width={32} height={32} className="object-contain" />
            {brandingWordmark ? (
              <img loading="lazy" src={brandingWordmark} alt={brandingAppName || "Observal"} width={192} height={24} className="h-6 max-w-48 object-contain" />
            ) : (
              <h1 className="text-2xl font-semibold tracking-tight font-[family-name:var(--font-display)]">{brandingAppName || "Observal"}</h1>
            )}
            <p className="text-sm text-muted-foreground">Approve a phone to edit account Following</p>
          </div>
          <div className="px-8 py-6">
            {approval.isSuccess ? (
              <div role="status" className="flex flex-col items-center gap-4 py-4 animate-in">
                <CheckCircle2 className="h-12 w-12 text-success" />
                <p className="text-center text-sm text-muted-foreground">Phone approved. You can close this tab and return to your phone.</p>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-2 animate-in">
                  <Label htmlFor="follow-code">Enter the one-device code shown on the phone you want to approve.</Label>
                  <Input id="follow-code" type="text" autoComplete="off" autoCapitalize="none" spellCheck={false} value={code} onChange={(event) => { setCode(event.target.value); setError(""); }} required autoFocus maxLength={32} className="text-center font-mono text-base tracking-wide" aria-invalid={!!error} aria-describedby={error ? "follow-error" : undefined} />
                </div>
                {error && (
                  <div id="follow-error" role="alert" className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2.5 text-sm text-destructive animate-in">
                    <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>{error}</span>
                  </div>
                )}
                {needsLogin && <Button type="button" variant="outline" onClick={signInAgain} className="w-full">Sign in again</Button>}
                <Button type="submit" disabled={approval.isPending || needsLogin} className="w-full">
                  {approval.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Approve this phone"}
                </Button>
              </form>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
