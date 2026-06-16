export interface RecentScan {
  scan_id: string
  target: string
  status: string
  risk_score: number | null
  risk_label: string | null
  started_at: string
}

// Client components call the same-origin BFF proxy, which injects auth and
// forwards to FastAPI. Resource paths here are relative to /api/<...>.
const BASE_URL = "/api/easm"

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

export interface ScanOptions {
  portRange?: string
  profile?: string
  modules?: string[]
}

export async function startScan(target: string, options: ScanOptions = {}) {
  return apiFetch<{ scan_id: string; status: string }>("/scans", {
    method: "POST",
    body: JSON.stringify({
      target,
      port_range: options.portRange,
      profile: options.profile,
      modules: options.modules,
      i_own_this_target: true,
    }),
  })
}

export async function getRecentScans() {
  try {
    return await apiFetch<RecentScan[]>("/scans")
  } catch {
    return []
  }
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
  return apiFetch<ScanStatus>(`/scans/${scan_id}/status`)
}

export async function getScanReport(scan_id: string) {
  return apiFetch<import("./types").ScanReport>(`/scans/${scan_id}`)
}

export async function getScanDiff(scan_id: string) {
  return apiFetch<import("./types").DiffResult>(`/scans/${scan_id}/diff`)
}

export interface TargetHistory {
  target: string
  scans: {
    scan_id: string
    status: string
    risk_score: number | null
    risk_label: string | null
    started_at: string | null
    completed_at: string | null
  }[]
}

export async function getTargetHistory(target: string) {
  return apiFetch<TargetHistory>(`/targets/${encodeURIComponent(target)}/history`)
}

// --- Schedules ---
import type { Schedule, Alert } from "./types"

export interface ScheduleCreate {
  target: string
  profile?: string
  port_range?: string
  modules?: string[]
  interval_minutes: number
}

export async function listSchedules() {
  return apiFetch<Schedule[]>("/schedules")
}

export async function createSchedule(payload: ScheduleCreate) {
  return apiFetch<Schedule>("/schedules", { method: "POST", body: JSON.stringify(payload) })
}

export async function toggleSchedule(id: string) {
  return apiFetch<Schedule>(`/schedules/${id}/toggle`, { method: "POST" })
}

export async function deleteSchedule(id: string) {
  return apiFetch<{ deleted: boolean }>(`/schedules/${id}`, { method: "DELETE" })
}

// --- Alerts ---
export async function listAlerts() {
  return apiFetch<Alert[]>("/alerts")
}

export async function markAlertRead(id: string) {
  return apiFetch<{ read: boolean }>(`/alerts/${id}/read`, { method: "POST" })
}

export async function markAllAlertsRead() {
  return apiFetch<{ updated: number }>("/alerts/read-all", { method: "POST" })
}
