/**
 * components/ScanInput.tsx
 * ------------------------
 * "use client"
 *
 * The main search box. Accepts a URL, domain, or IP address,
 * validates it client-side, calls the API, and returns the scan_id.
 *
 * PROPS:
 *   onScan: (scanId: string) => void
 *     Callback fired after a scan is successfully queued.
 *     The parent (page.tsx) uses this to navigate to /scan/{scanId}.
 *
 * STATE:
 *   value: string          current input value
 *   loading: boolean       true while waiting for API response
 *   error: string | null   validation or API error to display
 *
 * LAYOUT:
 *   A single row: [text input] [scan button]
 *   Below the row: error message in red if error is set.
 *   Optionally a small hint text below: "e.g. example.com · 192.168.1.1"
 *
 * CLIENT-SIDE VALIDATION (before calling the API):
 *   Run on submit, not on every keystroke.
 *   Strip leading/trailing whitespace.
 *   Strip protocol if present: remove "https://" or "http://"
 *   Strip path if present: take only the hostname part.
 *   Reject if empty after stripping.
 *   Reject if contains spaces.
 *   If it passes: call startScan(cleanedValue) from lib/api.ts.
 *
 *   Do NOT write a complex regex validator — the backend validates properly.
 *   Client-side is just a basic sanity check to avoid obvious empty submits.
 *
 * ON SUBMIT:
 *   1. Set loading = true, error = null
 *   2. Validate — if invalid, set error and return
 *   3. Call startScan(target) from lib/api.ts
 *   4. On success: call onScan(scan_id)
 *   5. On error: set error = the error message from the API
 *   6. Set loading = false in both cases (use try/finally)
 *
 * KEYBOARD:
 *   Pressing Enter in the input should submit (same as clicking the button).
 *   Add onKeyDown handler: if key === "Enter" call handleSubmit().
 *
 * WHILE LOADING:
 *   Disable both the input and the button.
 *   Show a spinner inside the button instead of the text "Scan".
 *   Use the Button component's disabled prop.
 *
 * SHADCN COMPONENTS USED:
 *   Input, Button
 *
 * EXAMPLE final cleaned values for these inputs:
 *   "https://example.com/about" → "example.com"
 *   "  192.168.1.1  "           → "192.168.1.1"
 *   "http://sub.domain.co.uk"   → "sub.domain.co.uk"
 */

"use client"

import * as React from "react"

import { Button } from "./ui/button"
import { Input } from "./ui/input"
import { startScan } from "@/lib/api"

type ScanInputProps = {
  onScan: (scanId: string) => void
}

function normalizeTarget(rawTarget: string) {
  let target = rawTarget.trim()
  if (!target) {
    return ""
  }

  const lowerTarget = target.toLowerCase()
  if (lowerTarget.startsWith("http://")) {
    target = target.slice(7)
  } else if (lowerTarget.startsWith("https://")) {
    target = target.slice(8)
  }

  const slashIndex = target.indexOf("/")
  if (slashIndex !== -1) {
    target = target.slice(0, slashIndex)
  }

  return target.trim()
}

export default function ScanInput({ onScan }: ScanInputProps) {
  const [value, setValue] = React.useState("")
  const [loading, setLoading] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)

  const handleSubmit = React.useCallback(async () => {
    setLoading(true)
    setError(null)

    const trimmed = value.trim()
    if (!trimmed) {
      setError("Enter a URL, domain, or IP address.")
      setLoading(false)
      return
    }

    if (/\s/.test(trimmed)) {
      setError("Targets may not contain spaces.")
      setLoading(false)
      return
    }

    const target = normalizeTarget(trimmed)
    if (!target) {
      setError("Enter a valid URL, domain, or IP address.")
      setLoading(false)
      return
    }

    try {
      const result = await startScan(target)
      onScan(result.scan_id)
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message)
      } else {
        setError("An unexpected error occurred.")
      }
    } finally {
      setLoading(false)
    }
  }, [onScan, value])

  const handleKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Enter") {
      event.preventDefault()
      void handleSubmit()
    }
  }

  return (
    <div className="flex w-full flex-col gap-2">
      <div className="flex w-full items-center gap-2">
        <Input
          value={value}
          onChange={(event) => setValue(event.target.value)}
          onKeyDown={handleKeyDown}
          disabled={loading}
          aria-invalid={!!error}
          placeholder="Enter a URL, domain, or IP"
          className="min-w-0"
        />
        <Button onClick={handleSubmit} disabled={loading} type="button">
          {loading ? (
            <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
          ) : (
            "Scan"
          )}
        </Button>
      </div>
      <p className="text-sm text-muted-foreground">e.g. example.com · 192.168.1.1</p>
      {error ? <p className="text-sm text-destructive">{error}</p> : null}
    </div>
  )
}
