"use client"

import * as React from "react"
import { signIn } from "next-auth/react"

const BOOT_LINES = [
  "easm// external attack surface management",
  "",
  "[ ok ] phosphor display .......... online",
  "[ ok ] crypto channel ............ established",
  "[ ok ] scan engine ............... ready",
  "[ !! ] authorization ............. REQUIRED",
]

export default function LoginPage() {
  const [isLoading, setIsLoading] = React.useState(false)
  const [shown, setShown] = React.useState(0)

  React.useEffect(() => {
    const reduce =
      typeof window !== "undefined" &&
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches
    if (reduce) {
      // Reduced-motion: reveal the full boot text immediately. This must run
      // post-mount (not in a render-time initializer) to avoid an SSR/client
      // hydration mismatch, so the setState here is intentional.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setShown(BOOT_LINES.length)
      return
    }
    const id = setInterval(() => {
      setShown((n) => {
        if (n >= BOOT_LINES.length) {
          clearInterval(id)
          return n
        }
        return n + 1
      })
    }, 180)
    return () => clearInterval(id)
  }, [])

  const booted = shown >= BOOT_LINES.length

  const handleSignIn = async () => {
    setIsLoading(true)
    try {
      await signIn("google", { redirect: true, callbackUrl: "/" })
    } catch {
      setIsLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <div className="w-full max-w-xl border border-border bg-card box-glow">
        {/* window title bar */}
        <div className="flex items-center justify-between border-b border-border px-3 py-1.5 text-xs text-phosphor-dim">
          <span>/dev/easm — secure shell</span>
          <span className="flex gap-1.5 text-phosphor-dim/50">
            <span>─</span>
            <span>□</span>
            <span>×</span>
          </span>
        </div>

        {/* boot sequence */}
        <div className="px-5 py-5 text-sm leading-relaxed">
          <pre className="font-mono whitespace-pre-wrap">
            {BOOT_LINES.slice(0, shown).map((line, i) => {
              const ok = line.startsWith("[ ok ]")
              const warn = line.startsWith("[ !! ]")
              const head = i === 0
              return (
                <div
                  key={i}
                  className={
                    head
                      ? "font-display text-2xl text-phosphor-bright glow-strong"
                      : warn
                        ? "text-amber"
                        : ok
                          ? "text-phosphor-dim"
                          : "text-phosphor"
                  }
                >
                  {line || " "}
                </div>
              )
            })}
            {!booted ? <span className="blink text-phosphor-bright">▋</span> : null}
          </pre>

          {/* auth prompt — appears once boot completes */}
          {booted ? (
            <div className="mt-5 border-t border-border pt-5">
              <p className="text-phosphor-dim">
                <span className="text-phosphor">operator@easm</span>
                <span className="text-phosphor-dim/60">:</span>
                <span className="text-cyan">~</span>
                <span className="text-phosphor-dim/60">$ </span>
                <span className="text-phosphor">auth --provider google</span>
              </p>
              <p className="mt-1 text-xs text-phosphor-dim/70">
                Access is gated. Sign in with the Google account authorized for this console.
              </p>

              <button
                onClick={handleSignIn}
                disabled={isLoading}
                className="group mt-4 flex w-full items-center justify-between border border-phosphor/60 px-4 py-2.5 text-left text-sm text-phosphor-bright transition-colors outline-none hover:bg-phosphor hover:text-primary-foreground focus-visible:ring-1 focus-visible:ring-phosphor disabled:opacity-50"
              >
                <span className="flex items-center gap-2">
                  <svg className="h-4 w-4" viewBox="0 0 24 24" fill="currentColor" aria-hidden>
                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
                  </svg>
                  authenticate with google
                </span>
                <span className="text-phosphor-dim group-hover:text-primary-foreground">
                  {isLoading ? "…" : "❯"}
                </span>
              </button>

              <p className="mt-4 text-xs text-phosphor-dim/50">
                No account? Ask the console administrator to authorize your address.
              </p>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  )
}
