/**
 * app/api/easm/[...path]/route.ts
 * -------------------------------
 * Backend-For-Frontend proxy. Client components call same-origin
 * `/api/easm/<path>`; this handler authenticates the NextAuth session and
 * forwards the request to the FastAPI backend with the shared internal secret
 * and the acting user's email. The browser never talks to FastAPI directly,
 * and the API rejects anything without these server-only credentials.
 */

import { NextRequest, NextResponse } from "next/server"
import { getToken } from "next-auth/jwt"

const API_URL = process.env.API_URL ?? "http://127.0.0.1:8000"
const INTERNAL_SECRET = process.env.INTERNAL_API_SECRET ?? ""

async function handler(
  req: NextRequest,
  ctx: { params: Promise<{ path: string[] }> }
) {
  const token = await getToken({ req, secret: process.env.NEXTAUTH_SECRET })
  if (!token?.email) {
    return NextResponse.json({ detail: "Unauthorized" }, { status: 401 })
  }

  const { path } = await ctx.params
  const url = `${API_URL}/api/${path.join("/")}${req.nextUrl.search}`

  const init: RequestInit = {
    method: req.method,
    headers: {
      "Content-Type": "application/json",
      "X-Internal-Secret": INTERNAL_SECRET,
      "X-User-Email": String(token.email),
    },
    cache: "no-store",
  }
  if (req.method !== "GET" && req.method !== "HEAD") {
    init.body = await req.text()
  }

  try {
    const resp = await fetch(url, init)
    const body = await resp.text()
    return new NextResponse(body, {
      status: resp.status,
      headers: {
        "Content-Type": resp.headers.get("Content-Type") ?? "application/json",
      },
    })
  } catch {
    return NextResponse.json(
      { detail: "Backend unavailable" },
      { status: 502 }
    )
  }
}

export {
  handler as GET,
  handler as POST,
  handler as PUT,
  handler as PATCH,
  handler as DELETE,
}
