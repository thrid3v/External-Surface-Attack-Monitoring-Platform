export interface RecentScan {
  scan_id: string
  target: string
  status: string
  risk_score: number | null
  risk_label: string | null
  started_at: string
}

const BASE_URL = process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ?? ""

async function apiFetch<T>(path: string, options: RequestInit = {}) {
  const response = await fetch(`${BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
    },
    ...options,
  })

  if (!response.ok) {
    const body = await response.json().catch(() => null)
    const message =
      body?.detail || body?.message || response.statusText || "Request failed"
    throw new Error(message)
  }

  return response.json() as Promise<T>
}

export async function startScan(target: string, portRange?: string) {
  return apiFetch<{ scan_id: string; status: string }>("/api/scans", {
    method: "POST",
    body: JSON.stringify({
      target,
      port_range: portRange,
      i_own_this_target: true,
    }),
  })
}

export async function getRecentScans() {
  return apiFetch<RecentScan[]>("/api/scans")
}

export interface ScanStatus {
  scan_id: string
  status: string
  current_module?: string | null
  modules_complete?: string[]
  started_at?: string
  error?: string
}

export async function getScanStatus(scan_id: string) {
  return apiFetch<ScanStatus>(`/api/scans/${scan_id}/status`)
}

export async function getScanReport(scan_id: string) {
  return apiFetch<import("./types").ScanReport>(`/api/scans/${scan_id}`)
}

