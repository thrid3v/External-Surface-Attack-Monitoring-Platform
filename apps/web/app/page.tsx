/**
 * app/page.tsx
 * ------------
 * The homepage. First thing users see when they open the app.
 * Two responsibilities: accept a new scan target, show recent scan history.
 *
 * LAYOUT (top to bottom):
 *   1. Header bar — app name "EASM Scanner" + tagline
 *   2. ScanInput component — the main search box
 *   3. Recent scans list — last 20 scans from GET /api/scans
 *
 * BEHAVIOUR:
 *
 *   On load:
 *     Call getRecentScans() from lib/api.ts and display the results
 *     in a list below the search box. Show a Skeleton loader while
 *     the data is fetching. If the list is empty, show a friendly
 *     empty state: "No scans yet — enter a URL or IP above to get started."
 *
 *   When ScanInput submits:
 *     ScanInput calls startScan() and receives a scan_id back.
 *     Use Next.js router.push() to navigate to /scan/{scan_id}.
 *     The results page handles all polling and display from there.
 *     Pass an onScan callback prop to ScanInput for this navigation.
 *
 *   Recent scans list:
 *     Each item shows: target, risk_label badge, risk_score, time ago.
 *     Clicking a row navigates to /scan/{scan_id}.
 *     Use the Badge component for risk_label.
 *     Color the badge by severity:
 *       CRITICAL → destructive variant
 *       HIGH     → orange (custom class or inline style)
 *       MEDIUM   → warning yellow
 *       LOW      → secondary
 *       MINIMAL  → outline
 *
 * THIS IS A SERVER COMPONENT by default in Next.js App Router.
 * The recent scans fetch can happen server-side — no useEffect needed.
 * ScanInput must be a Client Component ("use client") because it handles
 * user interaction. Import it here and it works seamlessly.
 *
 * SHADCN COMPONENTS USED:
 *   Badge, Card, CardHeader, CardContent, Skeleton
 *
 * FILE SIZE TARGET: keep this under 80 lines.
 * It is a layout/composition file — all the real logic lives in components.
 */


import Image from "next/image";

export default function Home() {
  return (
    <div className="flex flex-col flex-1 items-center justify-center bg-zinc-50 font-sans dark:bg-black">
      <main className="flex flex-1 w-full max-w-3xl flex-col items-center justify-between py-32 px-16 bg-white dark:bg-black sm:items-start">
        <Image
          className="dark:invert"
          src="/next.svg"
          alt="Next.js logo"
          width={100}
          height={20}
          priority
        />
        <div className="flex flex-col items-center gap-6 text-center sm:items-start sm:text-left">
          <h1 className="max-w-xs text-3xl font-semibold leading-10 tracking-tight text-black dark:text-zinc-50">
            To get started, edit the page.tsx file.
          </h1>
          <p className="max-w-md text-lg leading-8 text-zinc-600 dark:text-zinc-400">
            Looking for a starting point or more instructions? Head over to{" "}
            <a
              href="https://vercel.com/templates?framework=next.js&utm_source=create-next-app&utm_medium=appdir-template-tw&utm_campaign=create-next-app"
              className="font-medium text-zinc-950 dark:text-zinc-50"
            >
              Templates
            </a>{" "}
            or the{" "}
            <a
              href="https://nextjs.org/learn?utm_source=create-next-app&utm_medium=appdir-template-tw&utm_campaign=create-next-app"
              className="font-medium text-zinc-950 dark:text-zinc-50"
            >
              Learning
            </a>{" "}
            center.
          </p>
        </div>
        <div className="flex flex-col gap-4 text-base font-medium sm:flex-row">
          <a
            className="flex h-12 w-full items-center justify-center gap-2 rounded-full bg-foreground px-5 text-background transition-colors hover:bg-[#383838] dark:hover:bg-[#ccc] md:w-[158px]"
            href="https://vercel.com/new?utm_source=create-next-app&utm_medium=appdir-template-tw&utm_campaign=create-next-app"
            target="_blank"
            rel="noopener noreferrer"
          >
            <Image
              className="dark:invert"
              src="/vercel.svg"
              alt="Vercel logomark"
              width={16}
              height={16}
            />
            Deploy Now
          </a>
          <a
            className="flex h-12 w-full items-center justify-center rounded-full border border-solid border-black/[.08] px-5 transition-colors hover:border-transparent hover:bg-black/[.04] dark:border-white/[.145] dark:hover:bg-[#1a1a1a] md:w-[158px]"
            href="https://nextjs.org/docs?utm_source=create-next-app&utm_medium=appdir-template-tw&utm_campaign=create-next-app"
            target="_blank"
            rel="noopener noreferrer"
          >
            Documentation
          </a>
        </div>
      </main>
    </div>
  );
}
