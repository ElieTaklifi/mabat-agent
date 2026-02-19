# Execution Surface Security Dashboard

A standalone, zero-dependency browser UI for visualising software and execution-surface inventory data produced by the MABAT agent.

## File Structure

```
web-ui/
├── index.html   — markup & layout (no inline styles or scripts)
├── styles.css   — all visual styles, CSS variables, animations
├── app.js       — data loading, filtering, rendering logic
└── README.md    — this file
```

## Usage

1. Open `index.html` directly in any modern browser (Chrome, Edge, Firefox).  
   No web server required — all assets are local.
2. Click **Load inventory.json** in the top-right and select an exported inventory file from the agent.
3. The dashboard populates automatically with demo data until a real file is loaded.
4. Use the dedicated analyst tabs (`Registry`, `Autoruns`, `Services`, `Filesystem`) for source-specific triage.

## Views

### Dashboard tab
| Panel | Description |
|---|---|
| Stat cards | Total surfaces, high / medium / low risk counts |
| Risk Distribution | Animated SVG donut chart |
| Risk Breakdown | Percentage bars per risk level |
| By Source | Horizontal bars showing entry counts per scanner source |
| Top Publishers | Ranked leaderboard of software publishers |

### Inventory tab
Full filterable table of every discovered surface with query-builder filters (AND/OR logic).

**Key fields:** Severity · Name · Type · Source · Scope · Publisher · Version · Path · Why flagged · Explanation


## inventory.json Format (updated)

The dashboard expects a JSON object with an `entries` array.  
Each entry should conform to the following shape:

```jsonc
{
  "entries": [
    {
      "name":    "My App",          // required — display name
      "type":    "Win32",           // Win32 | UWP | Service | Driver | …
      "source":  "registry",        // registry | registry-msi | persistence | os_catalog | filesystem
      "scope":   "per-machine",     // per-machine | per-user
      "userSID": "S-1-5-21-…",     // or "N/A" for machine-wide installs
      "severity": "medium",
      "severityReasons": "No publisher recorded; No install date",
      "explanation": "Found in uninstall registry keys.",
      "metadata": {
        "path":           "C:/Program Files/MyApp",
        "publisher":      "Acme Corp",
        "displayVersion": "2.1.0",
        "registryPath":   "…\\Uninstall\\MyApp",
        "mechanism":      "run_key"
      }
    }
  ]
}
```

## Severity Model

The dashboard primarily consumes the severity fields provided by `inventory.json` (`severity`, `severityReasons`, and optional metadata hints).

Default visual tiers used across widgets and tables:
- `critical`
- `high`
- `medium`
- `low`

If severity fields are missing, fallback behavior in the UI logic applies source/type heuristics.

## Design

- **Fonts:** Syne (UI) + JetBrains Mono (data/code)  
- **Theme:** Dark blue-grey with coloured accent system via CSS custom properties  
- All colours are defined as CSS variables in `styles.css → :root` — easy to re-theme.
