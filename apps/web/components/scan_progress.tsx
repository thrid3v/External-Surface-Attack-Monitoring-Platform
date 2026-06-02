/**
 * components/ScanProgress.tsx
 * ---------------------------
 * "use client"
 *
 * Shows a live progress indicator while a scan is running.
 * Displayed by app/scan/[id]/page.tsx while status is pending/running.
 *
 * PROPS:
 *   currentModule: string | null
 *     The name of the scanner module currently running.
 *     Comes from ScanStatus.current_module in the API response.
 *     e.g. "port_scanner", "cve_lookup", "dns_enum"
 *   target: string
 *     The domain or IP being scanned. Shown in the UI.
 *
 * THE SIX MODULES IN ORDER:
 *   Define this as a constant array at the top of the file:
 *   const MODULES = [
 *     { key: "port_scanner",   label: "Port scan" },
 *     { key: "cve_lookup",     label: "CVE lookup" },
 *     { key: "dns_enum",       label: "DNS enumeration" },
 *     { key: "osint_fetcher",  label: "OSINT fetch" },
 *     { key: "service_probe",  label: "Service probe" },
 *     { key: "report_gen",     label: "Generating report" },
 *   ]
 *
 * LAYOUT:
 *   Large centered card with:
 *     - Title: "Scanning {target}..."
 *     - shadcn Progress bar (value = percentage complete)
 *     - List of all 6 modules, each showing:
 *         ✓ (check icon) if complete
 *         spinner if currently running
 *         dot/dash if not yet started
 *     - Estimated time note: "This usually takes 30–120 seconds"
 *
 * PROGRESS CALCULATION:
 *   Find the index of currentModule in the MODULES array.
 *   percentage = ((index + 1) / MODULES.length) * 100
 *   If currentModule is null (pending), percentage = 0.
 *   Pass this to the shadcn Progress component's value prop.
 *
 * MODULE STATUS LOGIC:
 *   For each module in MODULES:
 *     If its index < current module index → "complete" (show checkmark)
 *     If its key === currentModule        → "running"  (show spinner)
 *     Otherwise                          → "pending"  (show dash)
 *
 * SPINNER:
 *   Use a simple CSS animation or a Lucide icon with animate-spin class.
 *   Import Loader2 from lucide-react: <Loader2 className="animate-spin" />
 *
 * SHADCN COMPONENTS USED:
 *   Progress, Card, CardContent
 *
 * NOTE:
 *   This component is purely display — it receives props and renders.
 *   All polling logic lives in app/scan/[id]/page.tsx.
 *   This component just visualises whatever currentModule it receives.
 */