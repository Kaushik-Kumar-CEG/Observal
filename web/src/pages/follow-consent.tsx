// SPDX-FileCopyrightText: 2026 Kaushik Kumar <kaushikrjpm10@gmail.com>
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState } from "react";
import { useRouter } from "@tanstack/react-router";
import { AlertCircle, CheckCircle2, Loader2 } from "lucide-react";
import { clearSession } from "@/lib/api";
import { useAcceptFollowConsent, useFollowConsentState } from "@/hooks/use-api";
import { useDeploymentConfig } from "@/hooks/use-deployment-config";
import { Button } from "@/components/ui/button";

export default function FollowConsentPage() {
  const router = useRouter();
  const { brandingAppName, brandingLogo } = useDeploymentConfig();
  const [ready, setReady] = useState(false);
  const [checked, setChecked] = useState(false);
  const [error, setError] = useState("");
  const consentId = useRef<string | null>(null);
  const state = useFollowConsentState(ready);
  const consent = useAcceptFollowConsent();

  useEffect(() => {
    if (!sessionStorage.getItem("observal_access_token")) {
      router.navigate({ to: "/login", search: { next: "/follow/consent" }, replace: true });
    } else {
      setReady(true);
    }
  }, [router]);

  function signInAgain() {
    clearSession();
    router.navigate({ to: "/login", search: { next: "/follow/consent" }, replace: true });
  }

  async function accept(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!checked || !state.data || state.data.state !== "consent_required") return;
    setError("");
    consentId.current ??= crypto.randomUUID();
    try {
      await consent.mutateAsync({
        consent: true,
        consent_id: consentId.current,
        owner_generation: state.data.owner_generation,
      });
    } catch (cause) {
      const status = (cause as Error & { status?: number }).status;
      if (status === 401 || status === 403) {
        setError("This browser session cannot enable following. Sign in to the same HTTPS server and account, then try again.");
      } else if (status === 409) {
        consentId.current = null;
        await state.refetch();
        setError("The account changed while this page was open. Review its current state before trying again.");
      } else {
        setError("Following could not be enabled. Check the connection and retry; the server will not assume consent.");
      }
    }
  }

  if (!ready) return null;
  const current = state.data?.state;
  const stateError = (state.error as Error & { status?: number } | null)?.status;

  return (
    <main className="flex min-h-dvh items-center justify-center bg-surface-sunken p-6">
      <div className="w-full max-w-lg overflow-hidden rounded-lg border bg-card shadow-sm">
        <header className="border-b px-6 py-6 sm:px-8">
          <div className="flex items-center gap-3">
            <img loading="lazy" src={brandingLogo || "/observal-logo.svg"} alt="" width={32} height={32} />
            <span className="text-sm font-medium">{brandingAppName || "Observal"}</span>
          </div>
          <h1 className="mt-6 text-2xl font-semibold tracking-tight font-[family-name:var(--font-display)]">Follow this account across devices</h1>
          <p className="mt-2 text-sm text-muted-foreground">Choose on this signed-in browser before requesting separate approval for each phone.</p>
        </header>
        <div className="space-y-6 px-6 py-6 sm:px-8">
          {state.isPending ? (
            <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Checking account state…</p>
          ) : state.isError ? (
            <div role="alert" className="space-y-3 text-sm text-destructive">
              <p>Account follow state could not be verified. No change was made.</p>
              {stateError === 401 || stateError === 403 ? <Button variant="outline" onClick={signInAgain}>Sign in again</Button> : <Button variant="outline" onClick={() => state.refetch()}>Retry</Button>}
            </div>
          ) : current === "available" || consent.isSuccess ? (
            <div role="status" className="flex items-start gap-3 text-sm"><CheckCircle2 className="h-5 w-5 shrink-0 text-success" /><p>Account following is available. Return to your phone and request its separate write approval. This page does not approve a device.</p></div>
          ) : current === "consent_required" ? (
            <form onSubmit={accept} className="space-y-5">
              <div className="space-y-3 text-sm leading-relaxed text-muted-foreground">
                <p>Enabling this saves the registry items you follow under this account so approved devices can read them. A separate browser approval is required before a phone can edit them.</p>
                <p>Withdrawing consent or removing follows is a separate account action. A pending removal is not the same as completed erasure.</p>
                <p className="rounded-md border border-warning/40 bg-warning/10 p-3 text-foreground">Engineering QA only: the product privacy notice, lawful basis and retention wording still require owner approval. Do not use this page for real-person enrollment.</p>
              </div>
              <label className="flex cursor-pointer items-start gap-3 text-sm font-medium">
                <input type="checkbox" checked={checked} onChange={(event) => setChecked(event.target.checked)} className="mt-1 size-4 accent-primary" />
                <span>I choose to enable account following on this server. I understand that phone write access requires a separate approval.</span>
              </label>
              {error && <p role="alert" className="flex items-start gap-2 text-sm text-destructive"><AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />{error}</p>}
              <Button type="submit" disabled={!checked || consent.isPending} className="w-full">
                {consent.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Enable account following"}
              </Button>
            </form>
          ) : (
            <div role="status" className="space-y-3 text-sm"><p>Following cannot be enabled while this account is {current === "withdrawal_pending" ? "waiting for removal" : "disabled"}. No consent was recorded.</p><Button variant="outline" onClick={() => state.refetch()}>Check again</Button></div>
          )}
        </div>
      </div>
    </main>
  );
}
