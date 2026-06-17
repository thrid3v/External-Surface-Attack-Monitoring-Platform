/**
 * app/layout.tsx — root layout
 * Loads the terminal type system (VT323 display + JetBrains Mono body) and
 * lays the CRT scanline overlay over the whole app.
 */

import type { Metadata } from "next";
import { JetBrains_Mono, VT323 } from "next/font/google";
import "./globals.css";
import { cn } from "@/lib/utils";
import { Providers } from "./providers";

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains",
});

const vt323 = VT323({
  subsets: ["latin"],
  weight: "400",
  variable: "--font-vt323",
});

export const metadata: Metadata = {
  title: "easm // attack surface console",
  description: "External attack surface management — recon, scoring, and change monitoring.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={cn("dark h-full antialiased crt-scanlines", jetbrainsMono.variable, vt323.variable, "font-mono")}
    >
      <body className="min-h-full">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
