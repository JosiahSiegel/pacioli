# Pacioli Report Design System

This contract codifies the existing self-contained compliance report before environment filtering evolves it. It applies to the HTML and vanilla JavaScript emitted by `scanner/aggregate.py`; no external fonts, assets, or client framework are required.

## 1. Atmosphere & Identity

A sober, dark-first compliance command center for auditors and operators working through evidence, not a marketing surface. The signature is **evidence in layers**: restrained blue navigation frames calm charcoal reading surfaces, while severity colors are reserved for actual compliance status. Dark is the first-render baseline to prevent a bright flash in technical and low-light contexts; light remains a complete, equivalent reading mode.

## 2. Color

### Semantic dark/light token table

All generated report colors resolve through these semantic CSS variables. The report begins with the dark values in `:root`; `[data-theme="light"]` overrides them. `[data-theme="dark"]` repeats the dark contract explicitly, and the system selection follows the operating system preference.

| Role | Token | Dark (first render) | Light | Usage |
| --- | --- | --- | --- | --- |
| Page background | `--color-bg` | `#121820` | `#f5f7fb` | Document and main background |
| Primary surface | `--color-surface` | `#1b2532` | `#ffffff` | Panels, cards, controls |
| Subtle surface | `--color-surface-subtle` | `#253142` | `#eef2f8` | Tracks, table headings, pills |
| Raised surface | `--color-surface-raised` | `#202c3b` | `#fafcff` | Hovered or sticky controls |
| Primary text | `--color-fg` | `#f3f7fb` | `#172033` | Body and headings |
| Muted text | `--color-fg-muted` | `#b6c2d1` | `#536276` | Metadata and captions |
| Sidebar background | `--color-nav-bg` | `#101b2d` | `#0a2648` | Persistent navigation |
| Sidebar surface | `--color-nav-surface` | `#172a43` | `#0d3560` | Active or hovered navigation |
| Sidebar text | `--color-nav-fg` | `#e7f0fb` | `#eef6ff` | Navigation labels and fields |
| Sidebar muted text | `--color-nav-muted` | `#b8c9dd` | `#c7d8ea` | Navigation metadata |
| Default border | `--color-border` | `#38475a` | `#ccd5e1` | Cards, tables, fields |
| Subtle border | `--color-border-subtle` | `#2b3849` | `#e2e8f0` | Row separations |
| Accent | `--color-accent` | `#79b8ff` | `#075cc4` | Links, focus, selected state |
| Accent surface | `--color-accent-surface` | `#17395f` | `#e6f1ff` | Filter and information context |
| High / critical | `--color-danger` | `#ff8a8a` | `#b42318` | High and critical findings |
| High / critical surface | `--color-danger-surface` | `#54272f` | `#fff0f0` | High and critical backgrounds |
| Warning | `--color-warning` | `#ffd08a` | `#9a5d00` | Medium findings and cautions |
| Warning surface | `--color-warning-surface` | `#564222` | `#fff7e6` | Medium and warning backgrounds |
| Low / neutral | `--color-neutral` | `#bdc7d4` | `#66758a` | Low severity and secondary status |
| Success | `--color-success` | `#86d7a2` | `#187a3d` | Compliant and suppressed state |
| Success surface | `--color-success-surface` | `#1d4932` | `#e9f8ee` | Compliant backgrounds |
| Code surface | `--color-code-bg` | `#0e1724` | `#10223a` | HCL code blocks |
| Code foreground | `--color-code-fg` | `#d5ebff` | `#d5ebff` | HCL code blocks |
| Focus ring | `--color-focus` | `#9ecbff` | `#005fcc` | Keyboard focus visibility |
| Shadow | `--color-shadow` | `rgba(0, 0, 0, 0.28)` | `rgba(31, 48, 70, 0.12)` | Low-elevation separation |

### Rules

- No raw palette literal appears in generated markup, inline style, SVG attribute, or JavaScript style string. Raw color values are permitted only in the token declarations above.
- Accent denotes navigation, actions, links, focus, and filter state; severity colors denote report data only.
- Dark and light mode preserve the same hierarchy and semantic meaning. A theme change never changes compliance state.

## 3. Typography

- **Sans:** `-apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif` for readable system-native reports.
- **Mono:** `"SF Mono", Menlo, Consolas, monospace` for paths, check IDs, and remediation content.
- **Display / page heading:** `1.8em`, weight 600, line-height 1.2.
- **Section heading:** `1.4em`, weight 600, line-height 1.3.
- **Panel heading:** `1.15em`, weight 600, line-height 1.4.
- **Body:** `14px`, regular, line-height 1.5; no body text below this size.
- **Metadata and labels:** `0.78em–0.9em`, with uppercase labels using restrained tracking for scan summaries only.

## 4. Spacing & Layout

The base spacing unit is **4px**. The report uses `--space-1` (4px), `--space-2` (8px), `--space-3` (12px), `--space-4` (16px), `--space-5` (20px), `--space-6` (24px), and `--space-8` (32px); browser mechanics such as percentages and intrinsic grid tracks remain raw.

- **Desktop (above 900px):** a fixed 240px sidebar and a fluid, independently readable main region. The document scroll owns vertical reading; the sidebar remains sticky within that document scroll.
- **Narrow / tablet (900px and below):** the shell becomes one column, sidebar becomes flow content, and the main region uses `--space-4` padding.
- **Content stress:** cards use intrinsic grids, labels can wrap, code and unbroken paths may scroll within their own code context, and the primary reading surface must not force a horizontal page scroll at 375px.
- **Filter controls:** use wrapping clusters rather than width math; the live result count moves to the next line when necessary.

## 5. Components

### Environment-filter control

- **Structure:** labelled search field, labelled requirement select, severity buttons, environment cards/bars, and a live result count.
- **States:** default, active, hover, keyboard focus-visible, filtered, dimmed, empty, and reset. Filter mechanics remain owned by later implementation work.
- **Accessibility:** native controls have visible labels; buttons retain text labels; count updates use the existing status text without replacing report semantics; selected state is not color-only.
- **Layout:** controls form a wrapping cluster in the report header or sidebar; the document remains the scroll owner.

### Theme control

- **Structure:** `<label for="theme-select">Theme</label>` paired with a native `<select id="theme-select">` containing `Dark`, `Light`, and `System`.
- **States:** default dark when storage is unavailable, explicit dark, explicit light, system-resolved dark, system-resolved light, hover, focus-visible, disabled by no scripting only (the document remains readable).
- **Accessibility:** native select and label are keyboard-operable and announced together; the visible focus ring uses `--color-focus`; no icon-only theme control is allowed.
- **Persistence:** only validated explicit preferences are guarded through `localStorage` under the namespaced `pacioli.report.theme` key. `System` is a valid stored selection and continues to respond to `matchMedia` changes.

### Report surface primitives

Panels, KPI cards, status badges, data tables, code blocks, and findings use the semantic surface, border, text, and severity tokens. Their visual state is a class, never an inline palette declaration.

## 6. Motion & Interaction

- Navigation, buttons, cards, and interactive heatmap cells may transition only `transform`, `opacity`, `background-color`, `border-color`, and `box-shadow` over 120ms with `ease-out`; color changes are brief state feedback, not decorative animation.
- The theme switch changes values immediately to avoid a flash and never animates layout or runs a page-wide reveal.
- Under `@media (prefers-reduced-motion: reduce)`, transitions and transforms are disabled or reduced to instant state changes.
- Every interactive control exposes a hover, active where relevant, and `:focus-visible` state. Motion must communicate selection, routing, or filter state.

## 7. Depth & Surface

**Strategy: mixed tonal shift + restrained border.** Primary separation comes from dark/light surface ramps and `--color-border`; elevated sticky filters and KPI cards use a single low-opacity `--color-shadow` layer. Corners are compact (3–6px) to preserve a technical report character. There is no glass effect, large glow, or decorative gradient: depth clarifies scan hierarchy.

## 8. Accessibility Constraints & Accepted Debt

### WCAG 2.2 AA constraints

- Maintain WCAG 2.2 AA contrast: at least 4.5:1 for normal text and 3:1 for large text and meaningful non-text boundaries, including both dark and light themes.
- All links, buttons, selects, search fields, rows made interactive, and heatmap cells must have a visible `:focus-visible` indicator that meets SC 2.4.7 / 2.4.11 expectations.
- Theme choice and filtering are fully keyboard reachable, labelled in native semantics, and never rely on color alone; text/symbol navigation remains text-labelled and no emoji icons are added.
- Respect `prefers-reduced-motion`; the report remains usable with scripts unavailable or storage denied.
- Status colors and their surrounding surfaces satisfy WCAG 2.2 AA SC 1.4.3 and 1.4.11 in both themes.

### Accepted debt

| Item | Location | Why accepted | Owner / exit |
| --- | --- | --- | --- |
| Full rendered-browser contrast matrix | Generated report routes | This token-contract task validates renderer output structurally; route-by-route automated contrast and visual QA require the upcoming mechanics and report fixture work. | Report UI follow-up; run browser contrast and keyboard checks at 375/768/1280px before release. |
| Legacy filter semantics | `scanner/aggregate.py` findings filter | Todo 5 must not alter filter logic while establishing a theme contract. | Todo 6 owns environment filter behavior and will add/confirm every label and interactive-row keyboard contract. |
