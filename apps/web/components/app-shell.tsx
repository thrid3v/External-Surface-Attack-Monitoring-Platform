"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { useSession, signOut } from "next-auth/react"
import {
  LayoutDashboard,
  Crosshair,
  CalendarClock,
  Bell,
  Settings,
  ShieldCheck,
  LogOut,
} from "lucide-react"

import { cn } from "@/lib/utils"

const NAV = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/targets", label: "Targets", icon: Crosshair },
  { href: "/schedules", label: "Schedules", icon: CalendarClock },
  { href: "/alerts", label: "Alerts", icon: Bell },
  { href: "/settings", label: "Settings", icon: Settings },
]

function isActive(pathname: string, href: string) {
  return href === "/" ? pathname === "/" : pathname.startsWith(href)
}

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const { data: session } = useSession()
  const email = session?.user?.email ?? "Signed in"

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-sidebar-border bg-sidebar md:flex">
        <Link href="/" className="flex h-16 items-center gap-2.5 border-b border-sidebar-border px-5">
          <span className="grid h-8 w-8 place-items-center rounded-lg bg-primary/15 text-primary">
            <ShieldCheck className="h-5 w-5" />
          </span>
          <span className="font-heading text-base font-semibold tracking-tight">EASM</span>
        </Link>

        <nav className="flex-1 space-y-1 p-3">
          {NAV.map(({ href, label, icon: Icon }) => {
            const active = isActive(pathname, href)
            return (
              <Link
                key={href}
                href={href}
                className={cn(
                  "flex items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium transition-colors",
                  active
                    ? "bg-primary/15 text-primary"
                    : "text-sidebar-foreground/70 hover:bg-sidebar-accent hover:text-sidebar-foreground"
                )}
              >
                <Icon className="h-4 w-4" />
                {label}
              </Link>
            )
          })}
        </nav>

        <div className="border-t border-sidebar-border p-3">
          <div className="truncate px-2 pb-2 text-xs text-muted-foreground" title={email}>
            {email}
          </div>
          <button
            onClick={() => signOut({ callbackUrl: "/login" })}
            className="flex w-full items-center gap-2 rounded-xl px-3 py-2 text-sm font-medium text-sidebar-foreground/70 transition-colors hover:bg-sidebar-accent hover:text-sidebar-foreground"
          >
            <LogOut className="h-4 w-4" />
            Sign out
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-16 items-center justify-between border-b border-border bg-background/80 px-6 backdrop-blur md:justify-end">
          <Link href="/" className="flex items-center gap-2 md:hidden">
            <ShieldCheck className="h-5 w-5 text-primary" />
            <span className="font-heading font-semibold">EASM</span>
          </Link>
          <div className="flex items-center gap-3">
            <Link
              href="/alerts"
              className="grid h-9 w-9 place-items-center rounded-lg text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
              aria-label="Alerts"
            >
              <Bell className="h-4 w-4" />
            </Link>
            <span className="hidden text-sm text-muted-foreground sm:inline">{email}</span>
          </div>
        </header>
        <main className="flex-1 p-4 sm:p-6">{children}</main>
      </div>
    </div>
  )
}
