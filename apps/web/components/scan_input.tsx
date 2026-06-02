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