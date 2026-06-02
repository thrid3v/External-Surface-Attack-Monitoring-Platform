/**
 * components/ReportExport.tsx
 * ---------------------------
 * Lets the user download the scan report in two formats: JSON and PDF.
 * Sits at the bottom right of the results page.
 *
 * PROPS:
 *   report: ScanReport    the full scan report object
 *   target: string        used in the filename
 *
 * LAYOUT:
 *   Two buttons side by side:
 *     [↓ Export JSON]   [↓ Export PDF]
 *
 * JSON EXPORT:
 *   Create a Blob from JSON.stringify(report, null, 2).
 *   Create a temporary anchor element, set href to URL.createObjectURL(blob).
 *   Set download filename: "easm-{target}-{date}.json"
 *   Programmatically click the anchor, then revoke the object URL.
 *   This triggers a browser file download with no server request needed.
 *
 *   function downloadJSON() {
 *     const blob = new Blob([JSON.stringify(report, null, 2)],
 *                           { type: "application/json" })
 *     const url = URL.createObjectURL(blob)
 *     const a = document.createElement("a")
 *     a.href = url
 *     a.download = `easm-${target}-${new Date().toISOString().slice(0,10)}.json`
 *     a.click()
 *     URL.revokeObjectURL(url)
 *   }
 *
 * PDF EXPORT:
 *   Use the browser's built-in window.print() with a print-specific CSS class.
 *   Add a class "print-report" to the main results container.
 *   In globals.css add @media print rules that:
 *     - Hide the header, search box, tabs nav, and export buttons
 *     - Show all tab content (not just the active tab)
 *     - Add the target and date as a print header
 *   Call window.print() — the browser shows the print dialog.
 *   This avoids needing a PDF library.
 *
 *   Alternatively if you want a real PDF: use the 'jspdf' npm package.
 *   Install: npm install jspdf
 *   Build a simple text layout with the risk score, top CVEs, and port list.
 *   Only do this if window.print() output is not good enough.
 *
 * LOADING STATE:
 *   JSON export is instant — no loading state needed.
 *   PDF export (if using jspdf): show a brief spinner on the button.
 *
 * "use client" required for all DOM manipulation.
 *
 * SHADCN COMPONENTS USED:
 *   Button
 *
 * ICONS:
 *   Download from lucide-react on both buttons.
 */