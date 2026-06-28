import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { Slot } from "radix-ui"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "group/button inline-flex shrink-0 items-center justify-center gap-2 border font-mono text-sm whitespace-nowrap transition-colors outline-none select-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-40 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        // invert on hover — a terminal selection
        default:
          "border-phosphor/60 bg-transparent text-phosphor-bright hover:bg-phosphor hover:text-primary-foreground hover:glow-strong",
        outline:
          "border-border bg-bg-inset/40 text-phosphor-dim hover:border-phosphor/60 hover:bg-accent hover:text-phosphor",
        secondary:
          "border-border bg-transparent text-phosphor-dim hover:bg-accent hover:text-phosphor",
        ghost:
          "border-transparent bg-transparent text-phosphor-dim hover:bg-accent hover:text-phosphor-bright",
        destructive:
          "border-red/60 bg-transparent text-red hover:bg-red hover:text-background",
        link: "border-transparent text-cyan underline-offset-4 hover:underline",
      },
      size: {
        default: "h-9 px-3.5",
        xs: "h-6 px-2 text-xs [&_svg:not([class*='size-'])]:size-3",
        sm: "h-8 px-3",
        lg: "h-10 px-5",
        icon: "size-9",
        "icon-xs": "size-6 [&_svg:not([class*='size-'])]:size-3",
        "icon-sm": "size-8",
        "icon-lg": "size-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

function Button({
  className,
  variant = "default",
  size = "default",
  asChild = false,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean
  }) {
  const Comp = asChild ? Slot.Root : "button"

  return (
    <Comp
      data-slot="button"
      data-variant={variant}
      data-size={size}
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
