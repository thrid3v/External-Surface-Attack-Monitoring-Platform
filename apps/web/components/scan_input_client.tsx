"use client"

import { useRouter } from "next/navigation"

import ScanInput from "./scan_input"

export default function ScanInputClient() {
  const router = useRouter()

  return <ScanInput onScan={(scanId) => router.push(`/scan/${scanId}`)} />
}
