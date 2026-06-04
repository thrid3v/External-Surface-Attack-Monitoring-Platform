"use client";

import { useEffect, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

type SeverityLabel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "MINIMAL";

interface RiskScoreProps {
  score: number;
  label: SeverityLabel;
  severitySummary: Record<string, number>;
  target: string;
}

interface SeverityConfig {
  textColor: string;
  bgColor: string;
  borderColor: string;
  badgeClass: string;
}

const SEVERITY_CONFIG: Record<SeverityLabel, SeverityConfig> = {
  CRITICAL: {
    textColor: "text-red-500",
    bgColor: "bg-red-50",
    borderColor: "border-red-500",
    badgeClass: "bg-red-100 text-red-700 border-red-200",
  },
  HIGH: {
    textColor: "text-orange-500",
    bgColor: "bg-orange-50",
    borderColor: "border-orange-500",
    badgeClass: "bg-orange-100 text-orange-700 border-orange-200",
  },
  MEDIUM: {
    textColor: "text-yellow-500",
    bgColor: "bg-yellow-50",
    borderColor: "border-yellow-500",
    badgeClass: "bg-yellow-100 text-yellow-700 border-yellow-200",
  },
  LOW: {
    textColor: "text-blue-500",
    bgColor: "bg-blue-50",
    borderColor: "border-blue-500",
    badgeClass: "bg-blue-100 text-blue-700 border-blue-200",
  },
  MINIMAL: {
    textColor: "text-gray-500",
    bgColor: "bg-gray-50",
    borderColor: "border-gray-400",
    badgeClass: "bg-gray-100 text-gray-700 border-gray-200",
  },
};

interface StatBoxProps {
  count: number;
  severityLabel: string;
  textColor: string;
  bgColor: string;
}

function StatBox({ count, severityLabel, textColor, bgColor }: StatBoxProps) {
  return (
    <div
      className={`flex flex-col items-center justify-center rounded-lg p-3 ${bgColor} min-w-[72px]`}
    >
      <span className={`text-3xl font-bold leading-none ${textColor}`}>
        {count}
      </span>
      <span className="mt-1 text-xs font-medium uppercase tracking-wide text-gray-500">
        {severityLabel}
      </span>
    </div>
  );
}

const STAT_SEVERITIES: {
  key: string;
  label: string;
  textColor: string;
  bgColor: string;
}[] = [
  {
    key: "critical",
    label: "Critical",
    textColor: "text-red-500",
    bgColor: "bg-red-50",
  },
  {
    key: "high",
    label: "High",
    textColor: "text-orange-500",
    bgColor: "bg-orange-50",
  },
  {
    key: "medium",
    label: "Medium",
    textColor: "text-yellow-500",
    bgColor: "bg-yellow-50",
  },
  {
    key: "low",
    label: "Low",
    textColor: "text-blue-500",
    bgColor: "bg-blue-50",
  },
];

export default function RiskScore({
  score,
  label,
  severitySummary,
  target,
}: RiskScoreProps) {
  const [displayScore, setDisplayScore] = useState(0);

  const config = SEVERITY_CONFIG[label] ?? SEVERITY_CONFIG.MINIMAL;

  useEffect(() => {
    if (score === 0) {
      setDisplayScore(0);
      return;
    }

    const totalDuration = 800; // ms
    const increment = 2;
    const steps = Math.ceil(score / increment);
    const intervalMs = totalDuration / steps;

    let current = 0;
    const timer = setInterval(() => {
      current += increment;
      if (current >= score) {
        setDisplayScore(score);
        clearInterval(timer);
      } else {
        setDisplayScore(current);
      }
    }, intervalMs);

    return () => clearInterval(timer);
  }, [score]);

  return (
    <Card
      className={`w-full overflow-hidden border-l-4 ${config.borderColor} shadow-md`}
    >
      <CardContent className="flex flex-col gap-6 p-6 sm:flex-row sm:items-center sm:justify-between">
        {/* LEFT COLUMN */}
        <div className="flex flex-col items-start gap-2">
          <span
            className={`text-8xl font-extrabold leading-none tracking-tight ${config.textColor}`}
          >
            {displayScore}
          </span>
          <Badge
            variant="outline"
            className={`mt-1 px-3 py-1 text-sm font-semibold uppercase tracking-wider ${config.badgeClass}`}
          >
            {label}
          </Badge>
          <p className="text-sm text-muted-foreground">{target}</p>
        </div>

        {/* RIGHT COLUMN */}
        <div className="flex flex-wrap gap-3 sm:justify-end">
          {STAT_SEVERITIES.map(({ key, label: statLabel, textColor, bgColor }) => (
            <StatBox
              key={key}
              count={severitySummary[key] ?? 0}
              severityLabel={statLabel}
              textColor={textColor}
              bgColor={bgColor}
            />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
