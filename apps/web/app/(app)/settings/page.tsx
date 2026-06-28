"use client"

import * as React from "react"
import { Mail, Webhook, BellRing, Send, Check } from "lucide-react"

import {
  getNotificationSettings,
  updateNotificationSettings,
  testNotification,
  type NotificationTestResult,
} from "@/lib/api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { cn } from "@/lib/utils"

const SEVERITIES = [
  { id: "info", label: "Info" },
  { id: "warning", label: "Warning" },
  { id: "high", label: "High" },
  { id: "critical", label: "Critical" },
]

function Toggle({ on, onClick }: { on: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "border px-3 py-1 text-xs font-medium transition-colors",
        on
          ? "border-phosphor/50 bg-phosphor/10 text-phosphor"
          : "border-border text-muted-foreground"
      )}
    >
      {on ? "On" : "Off"}
    </button>
  )
}

export default function SettingsPage() {
  const [emailEnabled, setEmailEnabled] = React.useState(false)
  const [emailAddress, setEmailAddress] = React.useState("")
  const [webhookEnabled, setWebhookEnabled] = React.useState(false)
  const [webhookUrl, setWebhookUrl] = React.useState("")
  const [minSeverity, setMinSeverity] = React.useState("warning")
  const [ownerEmail, setOwnerEmail] = React.useState("")

  const [loading, setLoading] = React.useState(true)
  const [saving, setSaving] = React.useState(false)
  const [saved, setSaved] = React.useState(false)
  const [testing, setTesting] = React.useState(false)
  const [testResult, setTestResult] = React.useState<NotificationTestResult | null>(null)
  const [error, setError] = React.useState<string | null>(null)

  React.useEffect(() => {
    getNotificationSettings()
      .then((s) => {
        setEmailEnabled(s.email_enabled)
        setEmailAddress(s.email_address ?? "")
        setWebhookEnabled(s.webhook_enabled)
        setWebhookUrl(s.webhook_url ?? "")
        setMinSeverity(s.min_severity)
        setOwnerEmail(s.owner_email)
      })
      .catch(() => setError("Failed to load settings"))
      .finally(() => setLoading(false))
  }, [])

  const onSave = async () => {
    setSaving(true)
    setSaved(false)
    setError(null)
    try {
      await updateNotificationSettings({
        email_enabled: emailEnabled,
        email_address: emailAddress.trim() || null,
        webhook_enabled: webhookEnabled,
        webhook_url: webhookUrl.trim() || null,
        min_severity: minSeverity,
      })
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save")
    } finally {
      setSaving(false)
    }
  }

  const onTest = async () => {
    setTesting(true)
    setTestResult(null)
    setError(null)
    try {
      // Save first so the test exercises the current form values.
      await updateNotificationSettings({
        email_enabled: emailEnabled,
        email_address: emailAddress.trim() || null,
        webhook_enabled: webhookEnabled,
        webhook_url: webhookUrl.trim() || null,
        min_severity: minSeverity,
      })
      setTestResult(await testNotification())
    } catch (e) {
      setError(e instanceof Error ? e.message : "Test failed")
    } finally {
      setTesting(false)
    }
  }

  if (loading) {
    return <p className="text-sm text-muted-foreground">Loading…</p>
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="font-display text-3xl leading-none text-phosphor-bright glow">{"// notifications"}</h1>
        <p className="mt-1 text-xs text-phosphor-dim">
          how you&apos;re alerted when a re-scan surfaces new risk
        </p>
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0 pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Mail className="h-4 w-4 text-primary" /> Email
          </CardTitle>
          <Toggle on={emailEnabled} onClick={() => setEmailEnabled((v) => !v)} />
        </CardHeader>
        <CardContent className="space-y-2">
          <Input
            value={emailAddress}
            onChange={(e) => setEmailAddress(e.target.value)}
            placeholder={ownerEmail || "you@example.com"}
            disabled={!emailEnabled}
            className="font-mono"
          />
          <p className="text-xs text-muted-foreground">
            Leave blank to use your account email ({ownerEmail || "unknown"}).
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0 pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Webhook className="h-4 w-4 text-primary" /> Webhook
          </CardTitle>
          <Toggle on={webhookEnabled} onClick={() => setWebhookEnabled((v) => !v)} />
        </CardHeader>
        <CardContent className="space-y-2">
          <Input
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/…"
            disabled={!webhookEnabled}
            className="font-mono"
          />
          <p className="text-xs text-muted-foreground">
            A JSON payload is POSTed here. Works with Slack, Discord, Teams, or any endpoint.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <BellRing className="h-4 w-4 text-primary" /> Minimum severity
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {SEVERITIES.map((s) => (
            <button
              key={s.id}
              type="button"
              onClick={() => setMinSeverity(s.id)}
              className={cn(
                "border px-3 py-1 text-xs font-medium transition-colors",
                minSeverity === s.id
                  ? "border-primary/40 bg-primary/15 text-primary"
                  : "border-border text-muted-foreground"
              )}
            >
              {s.label}
            </button>
          ))}
        </CardContent>
      </Card>

      {error ? <p className="text-sm text-destructive">{error}</p> : null}
      {testResult ? (
        <Card>
          <CardContent className="space-y-1 py-4 text-sm">
            {testResult.detail ? (
              <p className="text-muted-foreground">{testResult.detail}</p>
            ) : (
              (["email", "webhook"] as const).map((ch) =>
                testResult[ch] ? (
                  <p key={ch} className={testResult[ch]!.ok ? "text-phosphor" : "text-destructive"}>
                    {testResult[ch]!.ok ? "✓" : "✗"} {ch}
                    {testResult[ch]!.error ? ` — ${testResult[ch]!.error}` : ""}
                  </p>
                ) : null
              )
            )}
          </CardContent>
        </Card>
      ) : null}

      <div className="flex items-center gap-3">
        <Button onClick={onSave} disabled={saving}>
          {saved ? <Check className="mr-1.5 h-4 w-4" /> : null}
          {saved ? "Saved" : saving ? "Saving…" : "Save"}
        </Button>
        <Button variant="outline" onClick={onTest} disabled={testing}>
          <Send className="mr-1.5 h-4 w-4" />
          {testing ? "Sending…" : "Send test"}
        </Button>
      </div>
    </div>
  )
}
