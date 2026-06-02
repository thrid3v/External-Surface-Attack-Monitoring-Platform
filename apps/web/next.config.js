/** @type {import('next').NextConfig} *\/
 *   const nextConfig = {
 *
 *     Environment variables exposed to the browser:
 *     Next.js only exposes env vars prefixed with NEXT_PUBLIC_ to
 *     client-side code. The API URL must be public since the browser
 *     makes the fetch calls directly.
 *     These are READ from your .env.local file automatically —
 *     you do not need to list them here unless you want build-time defaults.
 *
 *     API rewrites for development (optional but recommended):
 *     Instead of hardcoding http://localhost:8000 everywhere, you can
 *     proxy /api/* to the FastAPI server in development:
 *
 *       async rewrites() {
 *         return [
 *           {
 *             source: "/api/:path*",
 *             destination: "http://localhost:8000/api/:path*",
 *           },
 *         ]
 *       }
 *
 *     With this rewrite, lib/api.ts can use "/api/scans" instead of
 *     "http://localhost:8000/api/scans" — cleaner and avoids CORS
 *     issues in development since the request appears same-origin.
 *     Remove this rewrite in production (handled by your load balancer).
 *
 *   }
 *   module.exports = nextConfig
 *
 * NOTE:
 *   If you add the rewrites block, you can simplify lib/api.ts:
 *   const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? ""
 *   An empty string means "same origin" — the rewrite handles routing.
 *   In production set NEXT_PUBLIC_API_URL to your actual API domain.
 */