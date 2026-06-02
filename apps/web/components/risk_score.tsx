/**
 * components/RiskScore.tsx
 * ------------------------
 * Displays the overall risk score prominently at the top of the results page.
 * The first thing a user sees after a scan completes.
 *
 * PROPS:
 *   score: number          0-100 integer
 *   label: string          "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "MINIMAL"
 *   severitySummary: Record<string, number>
 *     e.g. { critical: 2, high: 5, medium: 3, low: 1 }
 *   target: string         shown as a subtitle
 *
 * LAYOUT:
 *   A wide Card containing two columns:
 *
 *   LEFT COLUMN:
 *     - Large number: the score (e.g. "72")
 *       Font size should be very large — use text-7xl or text-8xl.
 *       Color the number by severity (see color mapping below).
 *     - The risk label below the number in a Badge.
 *     - The target domain in small muted text below that.
 *
 *   RIGHT COLUMN:
 *     Four small stat boxes, one per severity:
 *       CRITICAL: count in red
 *       HIGH:     count in orange
 *       MEDIUM:   count in yellow
 *       LOW:      count in blue/muted
 *     Each box shows the count large and the label small below it.
 *
 * SEVERITY COLOR MAPPING:
 *   CRITICAL → text-red-500   / bg-red-50
 *   HIGH     → text-orange-500 / bg-orange-50
 *   MEDIUM   → text-yellow-500 / bg-yellow-50
 *   LOW      → text-blue-500  / bg-blue-50
 *   MINIMAL  → text-gray-500  / bg-gray-50
 *
 *   Apply the matching color to the big score number and to the
 *   border-left of the card for a strong visual signal.
 *
 * ANIMATION (optional but impactful):
 *   Animate the score number counting up from 0 to the final value
 *   when the component mounts. Use a simple useEffect with an interval
 *   that increments a display value by ~2 per frame until it reaches
 *   the real score. Duration: ~800ms.
 *   This makes the score feel dynamic rather than just appearing.
 *   If you implement this, the component needs "use client".
 *
 * SHADCN COMPONENTS USED:
 *   Card, CardContent, Badge
 *
 * NOTE:
 *   This is a display-only component — no API calls, no state beyond
 *   the optional count-up animation. Keep it simple and visually striking.
 *   A security person should be able to read the risk at a glance.
 */