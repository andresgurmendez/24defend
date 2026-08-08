# /reports-feature — Build/extend the "Reportes de Phishing" screen

Spec + implementation blueprint for the phishing-reports feature: a screen
showing how many sites were blocked / suspicious / verified, filterable by
date, with quick presets (hoy, últimos 7 días, este mes) — designed to make
the app's protection value visible to the user, not just react to threats
silently.

This feature doesn't exist yet. Invoke this skill when starting the first
version or resuming work on it later (new filter, new stat, backend
upgrade) so the design decisions below aren't re-litigated from scratch.

## What already exists (don't rebuild this)

| Piece | File | Notes |
|-------|------|-------|
| **Target screen (placeholder, already wired)** | `ios/TwentyFourDefend/Views/WeeklyReportsView.swift` | Reached from the hamburger menu (`DashboardView.swift:166`, case `.weeklyReports`). Currently just a "Muy pronto..." placeholder — **this is the file to fill in**, not a new one |
| Local event store | `ios/Shared/BlockLog.swift` | `UserDefaults` App Group `group.com.24defend.app`, key `blocked_domains`, cap **200 events**, `BlockEvent{domain, reason, severity, timestamp}` |
| Severity enum | `ios/Shared/BlockLog.swift:3-10` | `red` (blocked), `yellow` (warned), `green` (cleared by backend), `checked` (agent investigated, no fraud signal but not confirmed legit either) |
| Closest existing list UI | `ios/TwentyFourDefend/Views/BlockLogView.swift` | Flat reverse-chronological list, no counts, no filtering. Presented as a sheet from `DashboardView.swift:128-130` — a separate surface from the hamburger-menu reports page |
| Dashboard teaser | `ios/TwentyFourDefend/Views/DashboardView.swift` | Shows only `blockLog.prefix(3)` inline |
| Diagnostic panel (unrelated) | `ios/TwentyFourDefend/Views/DiagnosticView.swift`, `ios/Shared/DiagnosticLog.swift` | Raw dev log, not stats — don't confuse with this feature |
| Server telemetry | `backend/app/routes/telemetry.py:162-235` (`GET /telemetry/stats`) | Aggregates counts **globally across all devices**, no date range, no per-device filter. Fed by `ios/Shared/TelemetryClient.swift`, which is **write-only** — iOS never reads stats back from the server today |
| Storage | `24defend-domains` table, single PK `domain`, no sort key / GSI (`infra/stack.py:66-76`) | Telemetry rows use synthetic PK `telemetry#<event_type>#<YYYY-MM-DD>` — date isn't a queryable attribute, so a real date-range query means a `Scan` |

## Architecture decision: local-first MVP

Build the first version entirely from the on-device `BlockLog`, no backend
changes required:

- It already has `severity` + `timestamp` per event — everything a
  "bloqueados / sospechosos / verificados" breakdown needs.
- Matches the existing privacy pattern (`CLAUDE.md` → "Never record
  allowed/normal domains... Anonymous device UUID") — no new server-side
  per-device tracking needed for v1.
- Avoids the DynamoDB scan cost of a real date-range query against a table
  with no sort key.

Only reach for the backend extension (Phase 2 below) if the 200-event cap
or single-device scope becomes a real limitation (see Gotchas).

## Implementation checklist

1. **`ios/Shared/BlockLog.swift`** — add a date-range query helper, e.g.:
   ```swift
   public static func events(from: Date, to: Date = Date()) -> [BlockEvent] {
       load().filter { $0.timestamp >= from && $0.timestamp <= to }
   }
   ```
   Keep `load()`/`append()`/`clear()` as-is — `BlockLogView` depends on them.

2. **Fill in `ios/TwentyFourDefend/Views/WeeklyReportsView.swift`** (replace the placeholder body):
   - Quick-filter chips: **Hoy**, **7 días**, **Este mes**, **Personalizado**
     (custom opens a `DatePicker` range). Compute the `from` date per chip
     (`Calendar.current.date(byAdding:...)`), call `BlockLog.events(from:to:)`.
   - Stat cards by severity: bloqueados (`red`), sospechosos (`yellow` +
     `checked`), verificados/seguros (`green`). Count, don't just list.
   - Optional: a simple trend chart (count per day within the range) using
     **Swift Charts** — deployment target is iOS 16.0 (`ios/project.yml:5`),
     so `Charts` is available; not currently imported anywhere else in the
     app, so this is a genuinely new dependency to add via `import Charts`.
   - Value-framing copy for the header stat, matching the existing red
     notification tone (`CLAUDE.md` → "Sitio fraudulento confirmado..."):
     e.g. *"Te protegimos de N intentos de sitios falsos este mes."* Don't
     invent new severity colors — reuse `colorFor(_:)` pattern from
     `BlockLogView.swift:60-67` for visual consistency.

3. **Navigation is already wired** — `WeeklyReportsView` is reached from
   the hamburger menu (`DashboardView.swift:166`), no new entry point
   needed. Decide only whether it should also link out to `BlockLogView`
   for the raw per-event list (e.g. a "ver detalle" row per stat card),
   or stay self-contained. (Recommendation: keep `BlockLogView` as-is for
   raw history; `WeeklyReportsView` is the aggregated summary on top.)

4. No `xcodegen generate` needed for this step since `WeeklyReportsView.swift`
   already exists and is in the target — only re-run it if you add new
   files (per `CLAUDE.md` iOS project regeneration pattern).

## Phase 2 (only if needed): server-side aggregation

Needed only if you want reports to survive reinstall/app-data-reset, span
multiple devices, or exceed the 200-event local cap. Not required for v1.

- Add `device_id` + `from`/`to` query params to
  `GET /telemetry/stats` (`backend/app/routes/telemetry.py:162-235`).
- Because the table has no sort key/GSI, this stays a filtered `Scan` —
  fine at current data volume (per `/status` skill, table is dominated by
  the ~70K blacklist, telemetry rows are a small fraction), but if this
  grows, a real fix is a GSI on `device_id` + date — that's an `infra/stack.py`
  change and must go through CDK (`cdk deploy`), never a manual
  `aws dynamodb` call.
- `TelemetryClient.swift` would need a new read method — today it's
  write-only (batches events out, never fetches back).

## Gotchas

### 200-event local cap can roll over before "este mes" is over
A user hitting a lot of blocked/warned sites (e.g. during an active phishing
campaign) can blow through 200 events in less than a month, silently
truncating the "este mes" view. `BlockLog.append` in
`ios/Shared/BlockLog.swift:33-40` drops the oldest entries past the cap —
there's no signal to the UI that truncation happened. If this matters,
either raise `maxEntries` or surface "mostrando los últimos 200 eventos" in
the UI rather than implying it's complete.

### Local store is single-device, resets on reinstall
`UserDefaults` App Group data doesn't survive app deletion/reinstall and
doesn't sync across a user's devices. If the user churns phones or
reinstalls, "este mes" resets to zero — a value-demonstration feature that
occasionally shows 0 for tenured users is a bad look. Worth a design call,
not necessarily a blocker for v1.

### Don't confuse this with the diagnostic panel
`DiagnosticView`/`DiagnosticLog` (7-tap hidden panel) is a raw dev log for
debugging DNS/tunnel/notification issues — it is not user-facing stats and
isn't the right base to build on, even though it's the most recently added
"log viewer" in the codebase.

### `checked` severity needs a category, not a color guess
`checked` (agent investigated, no fraud signal, not confirmed legit) isn't
"blocked" or "cleared" — decide explicitly whether it counts toward
"sospechosos" or gets its own bucket in the stats cards. Silently lumping
it into one or the other changes what the number means.
