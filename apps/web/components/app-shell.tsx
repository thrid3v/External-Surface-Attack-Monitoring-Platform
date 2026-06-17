"use client"

import * as React from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { useSession, signOut } from "next-auth/react"

import { listAlerts } from "@/lib/api"
import { cn } from "@/lib/utils"

const NAV = [
  { href: "/", label: "dashboard" },
  { href: "/targets", label: "targets" },
  { href: "/schedules", label: "schedules" },
  { href: "/alerts", label: "alerts" },
  { href: "/settings", label: "settings" },
]

function isActive(pathname: string, href: string) {
  return href === "/" ? pathname === "/" : pathname.startsWith(href)
}

function currentLabel(pathname: string) {
  if (pathname === "/") return "dashboard"
  const seg = pathname.split("/").filter(Boolean)[0] ?? "dashboard"
  return seg
}

function useClock() {
  const [now, setNow] = React.useState<string>("--:--:--")
  React.useEffect(() => {
    const tick = () =>
      setNow(new Date().toLocaleTimeString("en-GB", { hour12: false }))
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [])
  return now
}

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const { data: session } = useSession()
  const email = session?.user?.email ?? "operator"
  const handle = email.split("@")[0] || "operator"
  const clock = useClock()

  const [unread, setUnread] = React.useState(0)
  React.useEffect(() => {
    let alive = true
    const load = () =>
      listAlerts()
        .then((a) => alive && setUnread(a.filter((x) => !x.read).length))
        .catch(() => {})
    load()
    const id = setInterval(load, 30000)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [pathname])

  const section = currentLabel(pathname)

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <div className="flex min-h-0 flex-1">
        {/* --- sidebar: the recon console pane --- */}
        <aside className="sticky top-0 hidden h-screen w-56 shrink-0 flex-col border-r border-border bg-sidebar md:flex">
          <Link
            href="/"
            className="flex h-14 items-center gap-2 border-b border-border px-4"
          >
            <span className="font-display text-3xl leading-none text-phosphor-bright glow-strong">
              easm
            </span>
            <span className="mt-1 text-[10px] uppercase tracking-[0.25em] text-phosphor-dim">
              v0.1
            </span>
          </Link>

          <nav className="flex-1 overflow-y-auto py-3 text-sm">
            <p className="px-4 pb-2 text-[10px] uppercase tracking-[0.25em] text-phosphor-dim/70">
              ~/console
            </p>
            {NAV.map(({ href, label }) => {
              const active = isActive(pathname, href)
              return (
                <Link
                  key={href}
                  href={href}
                  className={cn(
                    "flex items-center gap-2 border-l-2 px-4 py-1.5 transition-colors",
                    active
                      ? "border-phosphor bg-accent text-phosphor-bright"
                      : "border-transparent text-phosphor-dim hover:bg-accent/60 hover:text-phosphor"
                  )}
                >
                  <span className={cn(active ? "text-phosphor-bright" : "text-transparent")}>
                    ▸
                  </span>
                  <span className="truncate">~/{label}</span>
                  {label === "alerts" && unread > 0 ? (
                    <span className="ml-auto text-amber glow">[{unread}]</span>
                  ) : null}
                </Link>
              )
            })}
          </nav>

          <div className="border-t border-border p-3 text-xs">
            <div className="truncate px-1 pb-2 text-phosphor-dim" title={email}>
              <span className="text-phosphor">{handle}</span>
              <span className="text-phosphor-dim/60">@easm</span>
            </div>
            <button
              onClick={() => signOut({ callbackUrl: "/login" })}
              className="w-full border border-border px-2 py-1 text-left text-phosphor-dim transition-colors hover:border-red/60 hover:text-red"
            >
              $ logout
            </button>
          </div>
        </aside>

        {/* --- main column --- */}
        <div className="flex min-w-0 flex-1 flex-col">
          {/* top prompt bar */}
          <header className="sticky top-0 z-10 flex h-14 items-center justify-between gap-4 border-b border-border bg-background/90 px-4 backdrop-blur sm:px-6">
            <div className="flex items-center gap-2 font-mono text-sm">
              <Link href="/" className="font-display text-2xl leading-none text-phosphor-bright glow md:hidden">
                easm
              </Link>
              <span className="hidden text-phosphor-dim sm:inline">
                <span className="text-phosphor">{handle}@easm</span>
                <span className="text-phosphor-dim/60">:</span>
              </span>
              <span className="text-cyan">~/{section}</span>
              <span className="blink text-phosphor-bright">▋</span>
            </div>
            <Link
              href="/alerts"
              className="flex items-center gap-1.5 border border-border px-2 py-1 text-xs text-phosphor-dim transition-colors hover:border-phosphor/50 hover:text-phosphor"
            >
              alerts
              <span className={unread > 0 ? "text-amber glow" : "text-phosphor-dim/60"}>
                [{unread}]
              </span>
            </Link>
          </header>

          <main className="flex-1 p-4 sm:p-6">{children}</main>
        </div>
      </div>

      {/* --- bottom status line (tmux/vim) — the signature --- */}
      <footer className="sticky bottom-0 z-20 flex h-7 items-center gap-0 border-t border-border bg-sidebar text-[11px] tracking-wide">
        <span className="flex h-full items-center bg-phosphor px-2 font-bold text-primary-foreground">
          ONLINE
        </span>
        <span className="px-3 text-phosphor-dim">
          <span className="text-phosphor">{handle}@easm</span>
        </span>
        <span className="hidden px-3 text-phosphor-dim/70 sm:inline">~/{section}</span>
        <span className="flex-1 truncate px-3 text-phosphor-dim/40">
          {"·".repeat(120)}
        </span>
        <span className="px-3 text-phosphor-dim">
          alerts:<span className={unread > 0 ? "text-amber" : "text-phosphor"}>{unread}</span>
        </span>
        <span className="flex h-full items-center border-l border-border px-3 text-phosphor tabular-nums">
          {clock}
        </span>
      </footer>
    </div>
  )
}
