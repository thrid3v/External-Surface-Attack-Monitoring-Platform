"use client"

import * as React from "react"
import { Download } from "lucide-react"

import { Button } from "./ui/button"

interface ReportExportProps {
	report: unknown
	target: string
}

export default function ReportExport({ report, target }: ReportExportProps) {
	const downloadJSON = React.useCallback(() => {
		try {
			const blob = new Blob([JSON.stringify(report, null, 2)], {
				type: "application/json",
			})

			const url = URL.createObjectURL(blob)
			const a = document.createElement("a")
			a.href = url
			const date = new Date().toISOString().slice(0, 10)
			const safeTarget = target.replace(/[^a-z0-9-_]/gi, "-")
			a.download = `easm-${safeTarget}-${date}.json`
			document.body.appendChild(a)
			a.click()
			a.remove()
			URL.revokeObjectURL(url)
		} catch (err) {
			// swallow - downloads rarely fail in browser environments
			// consumer can add toast handling if desired
			// eslint-disable-next-line no-console
			console.error("Failed to download JSON report", err)
		}
	}, [report, target])

	const printReport = React.useCallback(() => {
		const date = new Date().toISOString().slice(0, 10)

		const cleanup = () => {
			try {
				document.body.classList.remove("print-report")
				delete (document.body as any).dataset.target
				delete (document.body as any).dataset.date
				window.removeEventListener("afterprint", cleanup)
			} catch (e) {
				// noop
			}
		}

		// Set attributes on the body so the print stylesheet can read them
		document.body.classList.add("print-report")
		;(document.body as any).dataset.target = target
		;(document.body as any).dataset.date = date

		// Cleanup after the print dialog closes
		window.addEventListener("afterprint", cleanup)

		// Trigger the browser print UI
		try {
			window.print()
		} catch (err) {
			// eslint-disable-next-line no-console
			console.error("window.print failed", err)
			cleanup()
		}
	}, [target])

	return (
		<div className="no-print flex items-center gap-2">
			<Button size="sm" variant="outline" onClick={downloadJSON}>
				<Download className="mr-2 h-4 w-4" />
				Export JSON
			</Button>

			<Button size="sm" variant="default" onClick={printReport}>
				<Download className="mr-2 h-4 w-4" />
				Export PDF
			</Button>
		</div>
	)
}
