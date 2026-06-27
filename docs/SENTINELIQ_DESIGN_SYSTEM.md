# SentinelIQ Design System — “Obsidian”

A premium, dark‑first design system for a Security Operations Center (SOC) console
that fuses **physical + cyber** security. It synthesizes the strongest patterns
from eleven best‑in‑class products into one cohesive language: dense operational
data rendered with clarity, speed, accessibility, and modern materials.

> Scope note: this analysis is grounded in the reference screenshots provided
> (Defender XDR, Sentinel, CrowdStrike Falcon, Splunk ES/Mission Control, Verkada
> Command, Datadog, Grafana, Genetec Security Desk, plus the design languages of
> IBM QRadar, TradingView, Linear, and Apple visionOS HIG). We borrow *patterns
> and principles*, never assets, and recombine them into an original system.

---

## 0. North star & principles

1. **Operator speed over chrome.** Every primary task is reachable in ≤2 keystrokes
   (Linear). Nothing decorative competes with signal.
2. **Severity is the loudest thing on screen — nothing else is.** Color is rationed;
   it almost always means *risk* (CrowdStrike/Splunk).
3. **Density is a setting, not a default.** Comfortable → Compact → Ultra; the same
   component scales (Datadog/Grafana).
4. **One entity, all its context.** Assets, users, cameras, incidents each get a
   unified page that correlates every related signal (Defender XDR entity pages +
   Datadog service summary).
5. **Triage is a queue + a flyout.** List on the left, investigate in a right panel
   without losing place (CrowdStrike detections).
6. **Materials create hierarchy, not boxes.** Layered surfaces and glass for
   transient/overlay UI (visionOS), hairline borders for persistent structure (Linear).
7. **Accessible by construction.** WCAG 2.2 AA minimum (AAA for body text), never
   color‑only encoding, full keyboard path, reduced‑motion honored.

---

## 1. What we take from each product (grounded in the screenshots)

| Product | The pattern in the image | What SentinelIQ adopts & why |
|---|---|---|
| **Microsoft Defender XDR** (light home) | Incident‑centric home; customizable **“Add cards”**; **3‑pip severity** glyph; entity roll‑ups (“Users at risk”, device compliance stacked bar); calm whitespace, “View all” affordances | Incident‑first dashboard, user‑customizable card grid, the severity‑pip micro‑indicator, and **entity roll‑up cards**. Defender proves a SOC home can be calm and still serious. |
| **Microsoft Sentinel** (dark overview + new quad overview) | Top **KPI strip with trend arrows + delta** (Events/Alerts/Incidents); **incidents‑by‑status segmented bar**; stacked time series with **categorical legend + per‑source totals**; **geo threat map** with glow markers; right rail “recent incidents” + **anomaly sparklines**; quadrant domain cards each with a “Manage X →” + a contextual CTA banner; MTTA/MTTC delta pills | The global KPI strip, status segmented bar, the **domain‑quadrant overview**, geo‑threat map, and the right **context rail**. Sentinel is our blueprint for *summarize → drill*. |
| **CrowdStrike Falcon** (EPP dashboard, **detections triage**, assets) | Oversized **thin‑weight KPI numerals**; **severity hexagon** glyph; donut‑with‑center‑total; **detections triage**: filter‑chip bar (Severity/Time/Status/Tactic/Technique/Actor…), “101 results (40,267 total)”, color‑tinted attribute cells, **right detail flyout**, Group‑by, bulk select; **saved filters**, tabbed dataset views, panel ⋮ menu + left panel‑edit rail | Our **triage table** is Falcon’s. We adopt the hexagon severity glyph, the filter‑chip bar, “N of M” counts, tinted attribute cells, the investigate flyout, saved views, and the editorial dark theme (near‑black + vivid category hues). |
| **Splunk Enterprise Security / SOC / Mission Control** | **Key Indicators strip** (Access/Endpoint/Network/Identity/Threat/UBA notables with +Δ red arrows); notable‑events‑by‑urgency bar; **sparkline‑in‑table** top‑N; **MITRE ATT&CK techniques‑by‑tactic matrix heatmap**; **disposition** breakdown (TP/FP/Benign %); **parallel‑sets** Owner→Status→Urgency→Disposition; **business‑value KPIs** (Dollars Saved, FTE Gained, Time Saved, Mean Dwell Time, MTTR); SLA gauge & analyst workload | The **Key Indicators strip** and the **MITRE matrix** are signature SOC artifacts we make first‑class. We add Splunk’s **business‑value exec KPIs**, disposition analytics, SLA/dwell tracking, and the parallel‑sets investigation analysis. |
| **Verkada Command** | Clean **camera video wall** (3‑col tiles, label overlay); top scope tabs (All Sites/Cameras/Access/Environment/Alarms); **map with clustered device pins**; **Floorplans**; incident as a **narrative timeline of clips** with People/Vehicles/Activity‑Log tabs; prominent **Lockdown**; responsive (desktop+mobile); rounded, bright, friendly | Physical‑security UX: the camera wall, clustered map, floorplans, **incident‑as‑clip‑timeline**, and the always‑visible **Lockdown** control. Verkada proves enterprise physical security can feel consumer‑grade. |
| **Datadog** (web perf, auth security, APM service) | **Template variables** ($Role, IP, username); event‑overlay search; **time‑range + playback**; **threshold bands** (Poor/Warning/Healthy) and **forecast/anomaly cones**; **hexagon hostmap**; ranked toplists with inline bars; color‑filled stat blocks (green success / red fail); **entity summary header** (Deployments/Errors/SLO/Incidents/Security cards) with status banner; choropleth | Dashboards become **composable + templated**. We take hostmap → **fleet/site health hexgrid**, threshold/forecast bands on every time series, the templated filter bar, and the **entity summary header** (one row of correlated module cards). |
| **Grafana** | **Stat panel** with sparkline background + threshold‑colored value; **gauge** & **bar‑gauge**; **gradient threshold bar**; **hexbin status grid**; threshold‑colored stacked series; table with Min/Max/Mean stat columns; **Cmd+K** “Search or jump to”; panel‑grid editing | Our visualization kit *is* Grafana‑grade: stat/gauge/bar‑gauge/threshold‑bar primitives, the panel grid with drag‑resize, and threshold coloring as a system token, not a one‑off. |
| **IBM QRadar** | Offense‑centric model; **magnitude** scoring (severity × relevance × credibility); offense prioritization; network/flow context | The **risk‑magnitude score** model for threats/incidents (a single 0–100 priority that fuses severity, asset criticality, confidence) and a network‑flow view. |
| **TradingView** | Pro charting; **synchronized crosshair** across panes; **data window** read‑out; watchlists; right data panel; keyboard; “this is a pro instrument” density | The **time‑synchronized crosshair** across all dashboard charts, a **data‑window** read‑out on hover, **watchlists** (pin assets/sites/users/threats), and pro‑grade chart interactions (zoom, brush‑to‑range). |
| **Linear** | **Command palette (Cmd+K)**; keyboard‑first; instant view transitions; restrained typography; hairline borders; purposeful micro‑motion; saved views; theming | The **command palette** as the spine of navigation + actions, keyboard shortcuts everywhere, the calm hairline aesthetic, and snappy 120–160ms transitions. Linear sets our craft bar. |
| **Apple visionOS HIG** | **Glass/material** layering with vibrancy & blur; depth hierarchy; soft large‑radius surfaces; generous focus states; Dynamic‑Type accessibility | **Materials** for transient UI (command palette, flyouts, the floating Ops Bar): translucent glass over content, depth = importance. Strong focus rings, large hit targets, scalable type. |

---

## 2. Foundations (tokens)

### 2.1 Color — “Obsidian” (dark, default) & “Daylight” (light)

Surfaces are a *ladder* (visionOS depth). Borders are hairlines (Linear). Severity
is the only saturated thing in the resting state (CrowdStrike/Splunk).

```
/* OBSIDIAN (dark, default) */
--bg-sunken:    #07090D;   /* app gutter, behind panels */
--bg-base:      #0A0C12;   /* app background (CrowdStrike near-black) */
--surface-1:    #10131A;   /* sections / nav */
--surface-2:    #161A23;   /* cards, panels */
--surface-3:    #1D222C;   /* popovers, menus, flyouts */
--surface-4:    #252B37;   /* hover / pressed */
--border-subtle:#FFFFFF0F; /* 6%  hairline */
--border:       #FFFFFF14; /* 8%  default */
--border-strong:#FFFFFF24; /* 14% emphasis / focus track */
--glass:        rgba(16,19,26,.72); /* + backdrop-blur(20px) saturate(1.4) */

--text-1: #EAEDF3;  --text-2: #A4ADBD;  --text-3: #6F7889;  --text-disabled:#4A5160;

--brand:      #6E8BFF;  /* “Iris” — selection, primary action, active nav */
--brand-strong:#5A78F0; --brand-soft: rgba(110,139,255,.14);
--accent:     #36E0E6;  /* “Signal” cyan — data highlight, links in data context */

/* Severity (canonical, color + glyph + label — never color alone) */
--sev-critical:#FF4D5E; --sev-high:#FF8A3C; --sev-medium:#FFC53D;
--sev-low:#46D39A;      --sev-info:#58A6FF;
--sev-*-bg: same hue @ 14% for tinted cells/chips; --sev-*-ring @ 40%

/* Status */
--ok:#34D399; --warn:#F5B544; --danger:#FF4D5E; --neutral:#8B93A3; --active:#6E8BFF;

/* Data-viz categorical (12, colorblind-tested in dark) */
#6E8BFF #36E0E6 #B98BFF #FFB020 #34D399 #FF6FA5
#8FD14F #4CC9F0 #F4795B #C792EA #59C3C3 #E5C07B

/* Threshold ramp (Grafana gradient bar / heatmaps / hostmap) */
#3A7BD5 → #34D399 → #8FD14F → #FFC53D → #FF8A3C → #FF4D5E
```

**Daylight (light)** mirrors the ladder: `--bg-base #F5F6F8`, `--surface-2 #FFFFFF`,
`--text-1 #0E1525`, `--border #0E152514`; severity/brand darkened ~6% for AA on white.
Theme is a single `data-theme` attribute swap; all components consume tokens only.

### 2.2 Typography

- **Sans:** Inter (UI). **Mono:** JetBrains Mono (IDs, IPs, hashes, timestamps,
  plate numbers, KQL/queries, log lines) — mono signals “machine data” (Splunk/QRadar/TradingView).
- **Tabular figures everywhere** in tables, KPIs, axes (`font-variant-numeric: tabular-nums`).
- **Hero numerals are thin (300) and large** (CrowdStrike) for KPI stats only.

```
display-xl  32/38  -0.02em  600
display     26/32  -0.01em  600
h1          21/28  -0.01em  600
h2          17/24           600
h3          15/20           600
body        14/20           400/500
body-sm     13/18           400      (table default)
caption     12/16           500
label-micro 11/14  +0.06em  600 UPPERCASE  (KPI labels, column heads — Splunk/CRWD)
kpi-hero    44/48  -0.02em  300 tabular   (stat numerals)
mono-13     13/18  / mono-12 12/16        (data cells, logs)
```

### 2.3 Spacing, grid, density

- 4px base: `2 4 8 12 16 20 24 32 40 48 64 80`.
- **12‑column fluid panel grid**, 16px gutter, drag‑resizable panels (Grafana/Azure tiles).
- **Density modes** (token swap on `data-density`): the same table/card adapts.

| Mode | Control h | Table row | Card pad | Use |
|---|---|---|---|---|
| Comfortable | 36 | 44 | 20 | executive views |
| Cozy *(default)* | 32 | 36 | 16 | most pages |
| Compact | 28 | 30 | 12 | triage, asset lists |
| Ultra | 26 | 26 | 10 | log/event streams (Splunk/Datadog) |

### 2.4 Radius, elevation, materials

```
radius: xs 4 (chips/cells) · sm 6 (controls) · md 8 (cards) · lg 12 (panels/flyouts) · xl 16 (modals) · pill 999
elevation (dark = lighter surface + hairline + soft shadow + top highlight):
  e0 surface-2, border-subtle
  e1 card:    border + 0 1 2 rgba(0,0,0,.3)
  e2 popover: surface-3 + 0 8 24 rgba(0,0,0,.45)
  e3 flyout/glass: --glass + blur + 0 16 48 rgba(0,0,0,.55)   (visionOS)
  e4 modal:   surface-3 + 0 24 64 rgba(0,0,0,.6) + scrim rgba(0,0,0,.5)
  top-highlight: inset 0 1 0 rgba(255,255,255,.05)
```

Glass (visionOS) is reserved for **transient/floating** layers — command palette,
the floating Ops Bar, flyouts, the lockdown sheet — never for resting content.

### 2.5 Motion

```
dur: 1=100ms 2=160ms 3=240ms 4=320ms
ease-standard:   cubic-bezier(.2,.8,.2,1)
ease-emphasized: cubic-bezier(.16,1,.3,1)   (panel/flyout in)
severity-pulse:  1.6s ease-in-out infinite  (critical live badge only)
```

View transitions ≤160ms (Linear). Charts animate on load only, never on tick.
`prefers-reduced-motion` → all non‑essential motion off, pulses become static rings.

### 2.6 Iconography & accessibility

- Line icons, 1.5px stroke, 20px grid (Lucide family already in the app).
- **Severity is encoded 3 ways**: color **+** hexagon glyph fill **+** text label
  (so it survives colorblindness and grayscale printing) — extends Defender’s pip.
- Focus: 2px `--brand` ring + 2px offset; visible on keyboard nav everywhere.
- Hit targets ≥32px (Comfortable ≥44). Contrast: text AA (AAA for body), non‑text AA.
- All charts have a data‑table fallback + `aria` summaries; live regions announce
  new criticals.

---

## 3. App shell & information architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  OPS BAR (glass, fixed): ◧ tenant ▾  |  ⌘K Search…  |  ◷ time range ▾  |  �...  │
│                                   ⚡live  🔔  ◐ density  ☾ theme  ⬛ LOCKDOWN  ◔ │
├───────────┬──────────────────────────────────────────────┬───────────────────┤
│  NAV RAIL │  Breadcrumb ›  Page title              actions │  CONTEXT DRAWER   │
│ (grouped) │ ───────────────────────────────────────────── │  (entity / detail │
│  Overview │                                                │   / investigate)  │
│  Sec Ops  │   PANEL GRID (12-col, drag-resizable)          │   — opens on row  │
│  AI Intel │                                                │     select; never │
│  Physical │                                                │     navigates away│
│  Cyber    │                                                │                   │
│  Analytics│                                                │                   │
│  Admin    │                                                │                   │
└───────────┴──────────────────────────────────────────────┴───────────────────┘
```

- **Nav rail** = Sentinel’s grouped sections (Overview / Security Operations / AI
  Intelligence / Physical Security / Cyber / Analytics / Administration) with a
  Verkada‑style collapsible icon rail and a pinned **Lockdown** at the bottom.
  *Influence:* Sentinel grouping + Verkada icon rail + Genetec/Verkada Lockdown.
- **Ops Bar** (glass, visionOS) holds: **tenant switcher** (multi‑tenant), the
  **Cmd+K** global search/command, a **global time‑range picker** with playback
  (Datadog), a **live toggle** (TradingView‑style real‑time), notifications,
  density + theme toggles, and the red **Lockdown** button.
- **Breadcrumbs** (Defender/Azure) for deep hierarchies (Org › Site › Zone › Camera).
- **Context Drawer** (right): the universal investigate/detail surface (CrowdStrike
  flyout). Selecting any row opens it; it’s resizable and pinnable.

**Added (missing) shell features for “million‑dollar” feel:**
- **Command palette** (Linear) — fuzzy nav + actions + entity jump + “run query”.
- **Saved views & view switcher** per module (CrowdStrike saved filters).
- **Watchlist tray** (TradingView) — pin any entity; live mini‑readouts.
- **Time‑travel scrubber** — a global timeline you can drag to replay state
  (fuses Verkada clip scrubber + Datadog playback + TradingView range brush).
- **Workspaces/tabs** — multiple open investigations as tabs (Genetec Security Desk).

---

## 4. Component library (each: influence → why)

**KPI Stat Card** — thin hero numeral + label‑micro + delta pill + sparkline bg.
*CrowdStrike numerals + Grafana stat sparkline + Sentinel/Splunk delta arrows.*
Why: the fastest possible “number + trend” unit; threshold‑colored value.

**Key Indicators Strip** — a row of domain notables with `+Δ` arrows.
*Splunk ES.* Why: the canonical SOC “is anything on fire?” band, top of every SOC page.

**Business‑Value KPI Row** — Dollars Saved / FTE Gained / Mean Dwell / MTTR / SLA%.
*Splunk Mission Control.* Why: executive justification; turns ops into ROI.

**Severity Glyph** — hexagon (fill = severity) + label; pip variant for inline.
*CrowdStrike hexagon + Defender pip.* Why: instant, accessible severity at any size.

**Magnitude Meter** — 0–100 priority bar (severity×asset‑criticality×confidence).
*IBM QRadar magnitude.* Why: one sortable number that beats raw severity for triage.

**Status Banner** — full‑width tinted strip (“OK: 7 monitors” / “3 criticals”).
*Datadog APM.* Why: page‑level health at a glance, color‑coded.

**Segmented Status Bar** — incidents by New/Active/Closed proportions inline.
*Sentinel.* Why: a distribution in one line, no chart needed.

**Donut + Legend‑Counts** — center total, right legend with counts.
*CrowdStrike / Sentinel Analytics donut.* Why: composition + total together.

**Time‑Series (threshold + forecast)** — stacked/line with Poor/Warn/Healthy bands,
dotted **forecast cone**, synchronized **crosshair** + **data‑window** readout.
*Datadog bands/forecast + TradingView crosshair + Grafana thresholds.*

**Sparkline‑in‑Cell** + **Bar‑in‑Cell** — micro‑trends inside tables.
*Splunk top‑N tables.* Why: trend without leaving the row.

**Hex Health Grid (hostmap)** — hexbin of sites/cameras/assets colored by health.
*Datadog hostmap + Grafana hexbin.* Why: fleet status for thousands of nodes in one view.

**Gauge / Bar‑Gauge / Gradient Threshold Bar** — *Grafana.* Why: bounded metrics
(uptime, SLA, disk) read better radially/as graded bars.

**Data Grid (Triage Table)** — sticky header, bulk‑select, **filter‑chip bar**,
Group‑by, color‑tinted attribute cells, virtualized rows, “N of M results”,
row → Context Drawer, column manager, density‑aware.
*CrowdStrike detections.* Why: the heart of SOC work; everything is a queue.

**Filter‑Chip Bar + Saved Filters** — typed facet chips (Severity/Time/Tactic/…).
*CrowdStrike + Datadog facets.* Why: composable, shareable, fast scoping.

**Detail Flyout / Context Drawer** — tabbed entity investigate panel.
*CrowdStrike flyout + Defender entity.* Why: investigate without losing the queue.

**Parallel Sets** — Owner→Status→Urgency→Disposition flow.
*Splunk SOC.* Why: see where work piles up across dimensions.

**MITRE ATT&CK Matrix** — tactics × techniques heatmap of counts/coverage.
*Splunk.* Why: the industry language for coverage & attribution.

**Disposition Breakdown** — TP / FP / Benign / Undetermined with %.
*Splunk.* Why: detection‑quality at a glance; tunes the program.

**Geo Threat Map** — dark map, glowing severity markers, in/out arcs.
*Sentinel.* Why: spatial threat context; great for a video‑wall.

**Choropleth** — logins/events by country shading.
*Datadog auth dashboard.* Why: behavioral geo‑risk (impossible travel, new country).

**Camera Tile / Video Wall** — responsive grid, label overlay, REC/live badge,
fullscreen, **map‑embedded camera tiles**.
*Verkada wall + Genetec map‑embedded cameras.* Why: live monitoring core.

**Operator Control Panel** — right rail for a selected device: PTZ, door
lock/unlock, talk‑down, snapshot, tile layout.
*Genetec Security Desk.* Why: act on the physical world from the console.

**Clip Timeline (Incident Narrative)** — ordered clips with timestamps +
People/Vehicles/Activity‑Log tabs.
*Verkada incident.* Why: tells the story of an event for response & evidence.

**Investigation Graph** — node‑link of entities/alerts/relations, expandable.
*Defender/Sentinel investigation graph.* Why: correlation is the analyst’s “aha”.

**Template Variables** — `$site $severity $time` selectors that re‑scope a whole page.
*Datadog/Grafana.* Why: one dashboard, infinite scopes; shareable deep links.

**Time‑Range Picker + Playback** — presets + custom + ◀▮▶ replay.
*Datadog.* Why: time is the universal filter in security.

**Command Palette** — fuzzy nav/actions/jump/run.
*Linear/Grafana Cmd+K.* Why: the power‑user spine; makes 200 pages feel like 1.

**Toasts / Live Region / Empty States / CTA Banners** — *Linear toasts; Sentinel
“improve coverage” banners.* Why: guidance + non‑blocking feedback.

**Lockdown Sheet** — glass confirm sheet with scope (site/zone/all) + reason.
*Verkada/Genetec Lockdown.* Why: the highest‑stakes action deserves a deliberate, beautiful, fast path.

---

## 5. Page blueprints (layout + influences + added features)

### 5.1 Executive Dashboard `/`
- **Layout:** Key Indicators strip → 4 **domain‑quadrant cards** (Threats, Incidents,
  Physical, Cyber) → Business‑Value KPI row → Geo threat map + Hex health grid →
  Recent activity rail.
- **Influences:** Sentinel quad overview (domains + “Manage →”), Splunk Key
  Indicators + business‑value KPIs, Datadog hostmap, Sentinel geo map, Defender
  “Add cards” customization.
- **Added:** drag‑to‑customize cards, exec “Daylight” print/export, anomaly callouts.

### 5.2 SOC Mission Control `/soc`
- **Layout:** Key Indicators → MTTA/MTTR/Dwell/SLA gauges → Cyber event **queue**
  (triage table) → Parallel‑sets (Owner→Status→Disposition) → Disposition % →
  analyst **workload** bars.
- **Influences:** Splunk ES + Mission Control (the entire SOC vocabulary),
  CrowdStrike triage table, Datadog status banner.
- **Added:** shift handover summary, “my queue” saved view, on‑call indicator.

### 5.3 Threat Center + MITRE Coverage `/threats`
- **Layout:** threat list sorted by **Magnitude** → **MITRE ATT&CK matrix** (coverage
  + live technique counts) → threat detail in Context Drawer → *Escalate to incident*.
- **Influences:** QRadar magnitude, Splunk MITRE matrix, CrowdStrike flyout.
- **Added:** technique → correlated detections drill, coverage gaps highlighted.

### 5.4 Incident Center `/incidents`
- **Layout:** incident **queue** (severity, SLA countdown, assignee, status) →
  incident detail = header (magnitude, SLA, owner) + **timeline** + **clip narrative**
  (physical) + linked alerts/assets + **evidence chain‑of‑custody** + **war‑room chat**.
- **Influences:** Defender incident roll‑up, Verkada clip‑timeline incident, Splunk
  disposition, CrowdStrike status flyout, Linear comments.
- **Added:** SLA breach countdown pills, war‑room (incident chat room), one‑click
  evidence seal, post‑incident report generator.

### 5.5 Investigation Graph `/investigate` *(NEW)*
- **Layout:** canvas node‑link (entities/alerts/relationships), expand‑on‑click,
  side inspector, timeline scrubber to replay how the graph grew.
- **Influences:** Defender/Sentinel investigation graph + TradingView scrubbing.
- **Why added:** the missing “connect the dots” surface that turns alerts into a story.

### 5.6 Hunting / Query Workspace `/hunt` *(NEW)*
- **Layout:** monaco query editor (SentinelIQ Query Language) + schema sidebar +
  results grid + “save as detection rule” + notebook cells.
- **Influences:** Sentinel Logs/Hunting + Splunk search + Datadog notebooks + TradingView.
- **Why added:** power analysts need ad‑hoc + repeatable hunting.

### 5.7 AI Detections `/detections`
- **Layout:** triage table (type, severity, confidence, camera/site, status) +
  filter chips + flyout with snapshot + risk‑engine score breakdown.
- **Influences:** CrowdStrike detections (1:1), Datadog facets.

### 5.8 Cyber / Login Monitoring `/cyber`
- **Layout:** Successful/Failed **color stat blocks** → severity tiles →
  Signals‑by‑Rule/IP/User toplists → **choropleth** logins by country → device list.
- **Influences:** Datadog Authentication Events dashboard (1:1), Splunk UBA.
- **Added:** impossible‑travel arc on map, device‑fingerprint trust timeline.

### 5.9 Live Monitoring `/live`
- **Layout:** **camera video wall** (grid presets 1/4/9/16) + **map‑embedded cameras**
  toggle + **Operator Control Panel** (PTZ/door/talk‑down) + event ticker.
- **Influences:** Verkada wall + Genetec map‑embedded cameras & operator rail.
- **Added:** AI‑detection overlays on tiles, “follow entity across cameras”.

### 5.10 Sites & Floorplans `/sites`
- **Layout:** site list + **floorplan canvas** with live device pins (cameras/doors/
  sensors) colored by health; clustered org map.
- **Influences:** Verkada floorplans + clustered map.
- **Added:** drag‑place devices, zone draw tool, occupancy heat overlay.

### 5.11 Entity Pages `/entity/:type/:id` *(NEW, unifying)*
- **Layout:** entity header + **correlated module cards** (Detections / Access /
  Incidents / Vulns / Network / Risk) + activity timeline + relationships.
- **Influences:** Defender entity pages + Datadog service summary header.
- **Why added:** one canonical page for asset/user/camera/vehicle/guard.

### 5.12 Analytics & BI `/analytics`
- **Layout:** **template‑variable bar** → panel grid (threshold series, hostmap,
  toplists, choropleth) → trends with forecast cones.
- **Influences:** Datadog + Grafana (templating, thresholds, forecast).

### 5.13 GIS Map `/map`
- Sentinel geo‑threat map + Verkada clustered pins + live guard/vehicle positions.

### 5.14 Reports Builder `/reports` *(NEW)*
- Drag panels → scheduled PDF/CSV → exec/daily/weekly templates.
- *Influences:* Azure dashboard editor + Splunk export + Defender exec reports.

### 5.15 Billing & SaaS `/billing`
- Plan/usage‑vs‑quota bars, invoices, payments. *Influences:* Datadog usage + Linear settings calm.

### 5.16 Administration `/admin`
- **RBAC permission matrix** (roles × permissions grid), feature flags, integrations,
  audit log viewer, tenant settings. *Influences:* Linear settings + Splunk admin +
  AWS IAM matrix. **Added:** visual permission matrix, audit hash‑chain verifier.

### 5.17 Command Palette (overlay, every page)
- Glass sheet (visionOS), fuzzy results grouped (Navigate / Actions / Entities /
  Recent), inline “run query”, keyboard‑only. *Influence:* Linear.

---

## 6. Interaction & micro‑patterns

- **Keyboard:** `⌘K` palette · `g` then key = go‑to · `j/k` move row · `x` select ·
  `e` escalate · `a` assign · `/` focus filter · `[` `]` resize drawer · `f` fullscreen
  panel · `?` shortcuts. *(Linear/TradingView.)*
- **Crosshair sync:** hovering any time chart shows a shared vertical cursor + data
  window across all panels in the view. *(TradingView.)*
- **Optimistic + undo:** status/assign mutate instantly with a 5s undo toast. *(Linear.)*
- **Live mode:** Ops‑Bar ⚡ streams updates; new criticals slide in with a pulse +
  audible chime (opt‑in) + live‑region announce.
- **Drill, don’t leave:** rows → drawer; panels → fullscreen; legends → filter the panel.

---

## 7. Density, responsive, accessibility

- **Responsive:** 3‑pane (rail+grid+drawer) ≥1440; drawer overlays 1024–1440; rail
  collapses to icons <1024; camera wall + key views are mobile‑usable (Verkada).
- **Density** swaps tokens app‑wide; tables remember per‑user choice.
- **A11y:** AA contrast (AAA body), 3‑way severity encoding, full keyboard,
  reduced‑motion, chart data‑table fallbacks, focus management in drawer/modal,
  scalable type (visionOS Dynamic Type ethos).

---

## 8. Implementation tokens (paste‑ready)

### 8.1 CSS custom properties (`obsidian.css`)
```css
:root[data-theme="obsidian"]{
  --bg-sunken:#07090D; --bg-base:#0A0C12; --surface-1:#10131A; --surface-2:#161A23;
  --surface-3:#1D222C; --surface-4:#252B37;
  --border-subtle:#ffffff0f; --border:#ffffff14; --border-strong:#ffffff24;
  --glass:rgba(16,19,26,.72);
  --text-1:#EAEDF3; --text-2:#A4ADBD; --text-3:#6F7889; --text-disabled:#4A5160;
  --brand:#6E8BFF; --brand-strong:#5A78F0; --brand-soft:rgba(110,139,255,.14);
  --accent:#36E0E6;
  --sev-critical:#FF4D5E; --sev-high:#FF8A3C; --sev-medium:#FFC53D;
  --sev-low:#46D39A; --sev-info:#58A6FF;
  --ok:#34D399; --warn:#F5B544; --danger:#FF4D5E; --neutral:#8B93A3;
  --radius-sm:6px; --radius-md:8px; --radius-lg:12px; --radius-xl:16px;
  --shadow-e1:0 1px 2px rgba(0,0,0,.3);
  --shadow-e2:0 8px 24px rgba(0,0,0,.45);
  --shadow-e3:0 16px 48px rgba(0,0,0,.55);
  --ease:cubic-bezier(.2,.8,.2,1); --ease-emph:cubic-bezier(.16,1,.3,1);
  --dur-1:100ms; --dur-2:160ms; --dur-3:240ms;
}
:root[data-theme="daylight"]{
  --bg-sunken:#ECEEF1; --bg-base:#F5F6F8; --surface-1:#FFFFFF; --surface-2:#FFFFFF;
  --surface-3:#FFFFFF; --surface-4:#F0F2F5;
  --border-subtle:#0e15250d; --border:#0e152514; --border-strong:#0e152526;
  --glass:rgba(255,255,255,.72);
  --text-1:#0E1525; --text-2:#47526A; --text-3:#6B7589; --text-disabled:#A2AAB8;
  --brand:#4F6BE6; --accent:#0E9CA6; /* severity same, darkened for AA on white */
}
[data-density="compact"]{ --row-h:30px; --ctl-h:28px; --card-pad:12px; }
[data-density="cozy"]   { --row-h:36px; --ctl-h:32px; --card-pad:16px; }
[data-density="comfy"]  { --row-h:44px; --ctl-h:36px; --card-pad:20px; }
.glass{ background:var(--glass); backdrop-filter:blur(20px) saturate(1.4);
        border:1px solid var(--border); box-shadow:var(--shadow-e3); }
.kpi-hero{ font:300 44px/48px Inter; font-variant-numeric:tabular-nums; letter-spacing:-.02em; }
```

### 8.2 Tailwind tokens (extend)
```js
theme:{ extend:{
  colors:{ bg:{sunken:'#07090D',base:'#0A0C12'},
    surface:{1:'#10131A',2:'#161A23',3:'#1D222C',4:'#252B37'},
    brand:{DEFAULT:'#6E8BFF',strong:'#5A78F0'}, accent:'#36E0E6',
    sev:{critical:'#FF4D5E',high:'#FF8A3C',medium:'#FFC53D',low:'#46D39A',info:'#58A6FF'} },
  fontFamily:{ sans:['Inter','system-ui'], mono:['JetBrains Mono','monospace'] },
  borderRadius:{ sm:'6px',md:'8px',lg:'12px',xl:'16px' },
  boxShadow:{ e1:'0 1px 2px rgba(0,0,0,.3)', e2:'0 8px 24px rgba(0,0,0,.45)', e3:'0 16px 48px rgba(0,0,0,.55)' },
  transitionTimingFunction:{ std:'cubic-bezier(.2,.8,.2,1)', emph:'cubic-bezier(.16,1,.3,1)' },
}}
```

---

## 9. Build roadmap (turning the spec into the running app)
1. **Token layer + theme switch** (obsidian/daylight, density) → reskin existing shell.
2. **Primitives:** KPI stat card, severity glyph, status banner, data grid + filter
   chips + Context Drawer, command palette.
3. **Viz kit:** threshold/forecast time series, donut+legend, hostmap hexgrid,
   gauge/bar‑gauge, sparkline‑in‑cell, MITRE matrix, geo map, choropleth.
4. **Signature pages:** SOC Mission Control, Incident Center + war‑room, Live
   Monitoring wall + operator panel, Investigation Graph, Entity pages.
5. **Power layer:** template variables, saved views, watchlist, time‑travel scrubber,
   crosshair sync, keyboard map, reports builder.

> Every token, component, and page above is original to SentinelIQ; the named
> products are cited only as the *rationale* for each pattern choice.
