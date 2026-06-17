import * as React from "react"

import { cn } from "@/lib/utils"

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "h-9 w-full min-w-0 border border-input bg-bg-inset px-3 py-1 font-mono text-sm text-phosphor caret-phosphor-bright transition-colors outline-none file:inline-flex file:h-7 file:border-0 file:bg-transparent file:text-sm file:text-phosphor placeholder:text-muted-foreground/60 focus-visible:border-phosphor/70 focus-visible:ring-1 focus-visible:ring-phosphor/40 disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-1 aria-invalid:ring-destructive/40",
        className
      )}
      {...props}
    />
  )
}

export { Input }
