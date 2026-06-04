"use client";

import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Check, Loader2, Minus } from "lucide-react";

const MODULES = [
  { key: "port_scanner", label: "Port scan" },
  { key: "cve_lookup", label: "CVE lookup" },
  { key: "dns_enum", label: "DNS enumeration" },
  { key: "osint_fetcher", label: "OSINT fetch" },
  { key: "service_probe", label: "Service probe" },
  { key: "report_gen", label: "Generating report" },
] as const;

type ModuleKey = (typeof MODULES)[number]["key"];
type ModuleStatus = "complete" | "running" | "pending";

interface ScanProgressProps {
  currentModule: string | null;
  target: string;
}

function getModuleStatus(
  moduleKey: ModuleKey,
  moduleIndex: number,
  currentIndex: number
): ModuleStatus {
  if (currentIndex === -1) return "pending";
  if (moduleIndex < currentIndex) return "complete";
  if (moduleKey === MODULES[currentIndex]?.key) return "running";
  return "pending";
}

function ModuleStatusIcon({ status }: { status: ModuleStatus }) {
  if (status === "complete") {
    return (
      <span className="flex h-5 w-5 items-center justify-center rounded-full bg-green-100">
        <Check className="h-3 w-3 text-green-600" strokeWidth={3} />
      </span>
    );
  }
  if (status === "running") {
    return (
      <span className="flex h-5 w-5 items-center justify-center">
        <Loader2 className="h-4 w-4 animate-spin text-blue-500" />
      </span>
    );
  }
  return (
    <span className="flex h-5 w-5 items-center justify-center">
      <Minus className="h-4 w-4 text-gray-300" />
    </span>
  );
}

export default function ScanProgress({ currentModule, target }: ScanProgressProps) {
  const currentIndex = currentModule
    ? MODULES.findIndex((m) => m.key === currentModule)
    : -1;

  const percentage =
    currentIndex === -1 ? 0 : ((currentIndex + 1) / MODULES.length) * 100;

  return (
    <div className="flex min-h-[60vh] items-center justify-center p-4">
      <Card className="w-full max-w-lg shadow-lg">
        <CardContent className="flex flex-col gap-6 p-8">
          {/* Header */}
          <div className="flex flex-col gap-1">
            <h2 className="text-xl font-semibold tracking-tight text-foreground">
              Scanning{" "}
              <span className="font-mono text-blue-600">{target}</span>
              <span className="animate-pulse">…</span>
            </h2>
            <p className="text-sm text-muted-foreground">
              This usually takes 30–120 seconds
            </p>
          </div>

          {/* Progress bar */}
          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span>Progress</span>
              <span>{Math.round(percentage)}%</span>
            </div>
            <Progress value={percentage} className="h-2" />
          </div>

          {/* Module list */}
          <ul className="flex flex-col gap-3">
            {MODULES.map((module, index) => {
              const status = getModuleStatus(
                module.key,
                index,
                currentIndex
              );

              return (
                <li
                  key={module.key}
                  className={`flex items-center gap-3 rounded-md px-3 py-2 transition-colors ${
                    status === "running"
                      ? "bg-blue-50"
                      : status === "complete"
                      ? "bg-green-50/60"
                      : "bg-transparent"
                  }`}
                >
                  <ModuleStatusIcon status={status} />
                  <span
                    className={`text-sm font-medium ${
                      status === "running"
                        ? "text-blue-700"
                        : status === "complete"
                        ? "text-green-700"
                        : "text-muted-foreground"
                    }`}
                  >
                    {module.label}
                  </span>
                  {status === "running" && (
                    <span className="ml-auto text-xs font-medium text-blue-500">
                      Running
                    </span>
                  )}
                  {status === "complete" && (
                    <span className="ml-auto text-xs text-green-500">Done</span>
                  )}
                </li>
              );
            })}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
