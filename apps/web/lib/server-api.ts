import "server-only"

import { getServerSession } from "next-auth"

import { authOptions } from "./auth"
import type { RecentScan } from "./api"
import type { Alert, Schedule } from "./types"

const API_URL = process.env.API_URL ?? "http://127.0.0.1:8000"
const INTERNAL_SECRET = process.env.INTERNAL_API_SECRET ?? ""

/**
 * Server-side fetch to FastAPI for use in Server Components. Reads the NextAuth
 * session and forwards the user identity + shared secret, mirroring the BFF
 * proxy used by client components.
 */
export async function serverFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const session = await getServerSession(authOptions)
  const email = session?.user?.email
  if (!email) {
    throw new Error("Not authenticated")
  }

  const response = await fetch(`${API_URL}/api${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      "X-Internal-Secret": INTERNAL_SECRET,
      "X-User-Email": email,
      ...(init.headers ?? {}),
    },
    cache: "no-store",
  })

  if (!response.ok) {
    throw new Error(`API request failed (${response.status})`)
  }
  return response.json() as Promise<T>
}

export interface TargetSummary {
  target: string
  last_scanned: string | null
  last_risk_score: number | null
  last_risk_label: string | null
  total_scans: number
}

export async function getRecentScansServer(): Promise<RecentScan[]> {
  try {
    return await serverFetch<RecentScan[]>("/scans")
  } catch {
    return []
  }
}

export async function getTargetsServer(): Promise<TargetSummary[]> {
  try {
    return await serverFetch<TargetSummary[]>("/targets")
  } catch {
    return []
  }
}

export async function getAlertsServer(): Promise<Alert[]> {
  try {
    return await serverFetch<Alert[]>("/alerts")
  } catch {
    return []
  }
}

export async function getSchedulesServer(): Promise<Schedule[]> {
  try {
    return await serverFetch<Schedule[]>("/schedules")
  } catch {
    return []
  }
}

