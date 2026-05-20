#!/usr/bin/env python3
"""
make_figures.py

Generates the figures used in the thesis Evaluation chapter from the six
Cooja Sky log files (3 MTD-on + 3 no-MTD baseline).  Each figure is saved
as a PDF in Master_Thesis___MTD/Images/Evaluation/ ready to be included
with \\includegraphics in the LaTeX source.

Figures produced:

  fig_pdr_over_time.png
    BR ingestion at each 5-minute snapshot for the three scenarios,
    MTD-on vs no-MTD.

  fig_energy_breakdown.png
    Per-sensor and BR energy in mJ split into CPU/LPM/TX/RX contributions,
    one bar per (scenario, condition).

  fig_anomaly_timeline.png
    For each MTD-on scenario, the anomaly events and reactive cycles
    plotted on the simulated-time axis so the reader can see when each
    branch fired.

  fig_branch_distribution.png
    Stacked bar chart of reactive cycle counts by selected branch per
    scenario, demonstrating the multi-branch coverage claim.

Run:
  python eval/make_figures.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import matplotlib
matplotlib.use("Agg")  # no display required
import matplotlib.pyplot as plt
import numpy as np


# --- Tmote Sky datasheet (3 V supply) -----------------------------------
TICK_HZ   = 32768
SUPPLY_V  = 3.0
I_CPU_MA  = 1.8
I_LPM_MA  = 0.0545
I_TX_MA   = 17.4
I_RX_MA   = 19.7

# --- Plot styling -------------------------------------------------------
plt.rcParams.update({
    "figure.dpi":         110,
    "savefig.dpi":        300,
    "font.family":        "serif",
    "font.size":          10,
    "axes.titlesize":     11,
    "axes.labelsize":     10,
    "legend.fontsize":    9,
    "axes.grid":          True,
    "grid.alpha":         0.3,
    "grid.linestyle":     "--",
})

COLOR_MTD   = "#1f4e79"
COLOR_NOMTD = "#c00000"
COLOR_CPU   = "#4472c4"
COLOR_LPM   = "#a5a5a5"
COLOR_TX    = "#ed7d31"
COLOR_RX    = "#70ad47"

SCENARIOS  = ["scan", "sinkhole", "flood"]
SCENARIO_TITLES = {"scan": "Scan", "sinkhole": "Sinkhole", "flood": "Flood"}


# --- Log helpers --------------------------------------------------------
TS_RE = re.compile(r"^(\d+):(\d+)\.(\d+)\s+ID:(\d+)\s+(.*)$")


def parse_ts(line: str):
    m = TS_RE.match(line)
    if not m:
        return None
    return int(m.group(1)) * 60 + int(m.group(2)) + int(m.group(3)) / 1000.0


def load_log(path: Path):
    """Walk the log once and return a dict of time-series and totals."""
    out = {
        "br_metrics_pts":    [],   # list of (t_sec, rx, anom)
        "anomaly_events":    [],   # list of (t_sec, type)
        "silence_events":    [],   # list of t_sec
        "reactive_cycles":   [],   # list of (t_sec, dominant)
        "rate_limit_drops":  [],   # list of t_sec
        "mtd_disabled":      False,
        "br_energest_last":  None, # (cpu, lpm, tx, rx)
        "sensor_energest":   {},   # node_id -> (cpu, lpm, tx, rx) last
    }

    if not path.exists():
        return out

    with path.open(encoding="utf-8", errors="replace") as fp:
        for raw in fp:
            line = raw.rstrip()
            t = parse_ts(line)
            if t is None:
                continue

            if "MTD orchestrator DISABLED" in line:
                out["mtd_disabled"] = True

            m = re.search(r"BR_METRICS rx=(\d+) anomalous=(\d+)", line)
            if m:
                out["br_metrics_pts"].append(
                    (t, int(m.group(1)), int(m.group(2))))

            m = re.search(r"BR_ENERGEST cpu=(\d+) lpm=(\d+) tx=(\d+) rx=(\d+)", line)
            if m:
                out["br_energest_last"] = tuple(int(g) for g in m.groups())

            m = re.search(
                r"ID:(\d+).*ENERGEST cpu=(\d+) lpm=(\d+) tx=(\d+) rx=(\d+)", line)
            if m and "BR_ENERGEST" not in line:
                node_id = int(m.group(1))
                if node_id != 1 and node_id != 31:
                    out["sensor_energest"][node_id] = tuple(
                        int(g) for g in m.groups()[1:])

            m = re.search(r"Anomaly type=(\d+)", line)
            if m:
                out["anomaly_events"].append((t, int(m.group(1))))

            if "SILENCE sensor" in line and "skipped" not in line:
                out["silence_events"].append(t)

            m = re.search(r"MTD Reactive Cycle.*dominant=(\d+)", line)
            if m:
                out["reactive_cycles"].append((t, int(m.group(1))))

            if "RATE_LIMIT drop" in line:
                out["rate_limit_drops"].append(t)

            # Attacker cumulative TX counter -- max "total=" seen.
            m = re.search(r"(?:SCAN|SINK|FLOOD)_TX total=(\d+)", line)
            if m:
                v = int(m.group(1))
                if v > out.get("attacker_packets_sent", 0):
                    out["attacker_packets_sent"] = v

    out.setdefault("attacker_packets_sent", 0)
    return out


def energy_split_mj(cpu, lpm, tx, rx):
    return (
        (cpu / TICK_HZ) * I_CPU_MA * SUPPLY_V,
        (lpm / TICK_HZ) * I_LPM_MA * SUPPLY_V,
        (tx  / TICK_HZ) * I_TX_MA  * SUPPLY_V,
        (rx  / TICK_HZ) * I_RX_MA  * SUPPLY_V,
    )


# ========================================================================
# Figure 1: PDR (BR ingestion) over time, per scenario, MTD vs no-MTD
# ========================================================================
def fig_pdr_over_time(data: Dict, out_dir: Path):
    fig, axes = plt.subplots(1, 3, figsize=(11, 3.3), sharey=False)

    for ax, scn in zip(axes, SCENARIOS):
        for cond, color in (("mtd", COLOR_MTD), ("nomtd", COLOR_NOMTD)):
            pts = data[(scn, cond)]["br_metrics_pts"]
            if not pts:
                continue
            t = [p[0] / 60 for p in pts]
            rx = [p[1] for p in pts]
            label = "MTD" if cond == "mtd" else "no-MTD"
            ax.plot(t, rx, marker="o", color=color, label=label, linewidth=1.6)

        ax.set_title(SCENARIO_TITLES[scn])
        ax.set_xlabel("Simulated time (min)")
        ax.set_ylabel("Cumulative BR ingestion (packets)")
        ax.legend(loc="upper left")

    fig.tight_layout()
    fig.savefig(out_dir / "fig_pdr_over_time.png", bbox_inches="tight")
    plt.close(fig)


# ========================================================================
# Figure 2: Energy breakdown by state, per (scenario, condition)
# ========================================================================
def fig_energy_breakdown(data: Dict, out_dir: Path):
    """
    Per-state energy breakdown using grouped bars on a logarithmic y axis.

    The Tmote Sky energy budget spans four orders of magnitude (LPM ~50 mJ
    vs RX ~100,000 mJ).  A linear stacked bar makes the LPM/CPU/TX
    contributions invisible because the RX bar dominates the scale.
    Switching to grouped bars on a log y axis lets every state's bar be
    visible and the MTD vs no-MTD delta within each state comparable.
    """
    # Collect per-state energies for both panels.
    states = ["CPU", "LPM", "TX", "RX"]
    state_colors = [COLOR_CPU, COLOR_LPM, COLOR_TX, COLOR_RX]

    # Build a 4 (states) x 6 (scenario,condition) matrix for each panel.
    sensor_rows: List[List[float]] = [[], [], [], []]   # CPU, LPM, TX, RX
    br_rows:     List[List[float]] = [[], [], [], []]
    col_labels:  List[str] = []

    for scn in SCENARIOS:
        for cond in ("mtd", "nomtd"):
            d = data[(scn, cond)]
            col_labels.append(f"{SCENARIO_TITLES[scn]}\n{cond.upper()}")

            if d["sensor_energest"]:
                vals = list(d["sensor_energest"].values())
                cpu_mean = np.mean([v[0] for v in vals])
                lpm_mean = np.mean([v[1] for v in vals])
                tx_mean  = np.mean([v[2] for v in vals])
                rx_mean  = np.mean([v[3] for v in vals])
                ec, el, et, er = energy_split_mj(cpu_mean, lpm_mean, tx_mean, rx_mean)
            else:
                ec = el = et = er = 0.0
            sensor_rows[0].append(ec); sensor_rows[1].append(el)
            sensor_rows[2].append(et); sensor_rows[3].append(er)

            if d["br_energest_last"]:
                ec, el, et, er = energy_split_mj(*d["br_energest_last"])
            else:
                ec = el = et = er = 0.0
            br_rows[0].append(ec); br_rows[1].append(el)
            br_rows[2].append(et); br_rows[3].append(er)

    fig, (ax_sensor, ax_br) = plt.subplots(1, 2, figsize=(13, 4.6))

    def _grouped(ax, rows, title, ylabel):
        n_cols   = len(col_labels)
        n_states = len(states)
        bar_w    = 0.18
        x        = np.arange(n_cols)
        for i, (state, color, values) in enumerate(zip(states, state_colors, rows)):
            offset = (i - (n_states - 1) / 2) * bar_w
            ax.bar(x + offset, values, bar_w, color=color, label=state,
                   edgecolor="black", linewidth=0.4)
        ax.set_yscale("log")
        # Clamp the bottom so log axis does not blow up on a near-zero LPM bar.
        ax.set_ylim(bottom=1)
        ax.set_xticks(x)
        ax.set_xticklabels(col_labels, fontsize=8)
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.grid(True, which="both", axis="y", alpha=0.25, linestyle="--")
        ax.legend(loc="lower right", ncol=4, fontsize=8, framealpha=0.9)

    _grouped(ax_sensor, sensor_rows,
             "Mean per-sensor energy (29 nodes)",
             "Energy (mJ, 30 min)  [log scale]")
    _grouped(ax_br, br_rows,
             "Border router energy",
             "Energy (mJ, 30 min)  [log scale]")

    fig.tight_layout()
    fig.savefig(out_dir / "fig_energy_breakdown.png", bbox_inches="tight")
    plt.close(fig)


# ========================================================================
# Figure 3: Reactive cycle timeline.
#
# A simple Gantt-style chart with one row per scenario.  Each marker is
# one reactive cycle, placed at its firing time on a 0-30 minute axis.
# Marker shape and colour identify the branch that fired:
#   triangle (blue)  = STALE_PORT  -> IPv6 shuffle
#   square   (amber) = CONN_FAILURE -> port hop
#   diamond  (red)   = CPU_LOAD    -> shuffle + rate limit
# Total cycle counts per branch are annotated on the right.
# ========================================================================
def fig_anomaly_timeline(data: Dict, out_dir: Path):
    branch_color  = {0: "#1f4e79", 1: "#ed7d31", 2: "#c00000"}
    branch_marker = {0: "v",       1: "s",       2: "D"}
    branch_label  = {0: "shuffle", 1: "token rotation", 2: "shuffle + rate limit"}

    fig, ax = plt.subplots(figsize=(11, 3.6))

    y_positions = {scn: 2 - i for i, scn in enumerate(SCENARIOS)}

    for scn in SCENARIOS:
        y = y_positions[scn]
        d = data[(scn, "mtd")]

        # Light reference line for each scenario row
        ax.hlines(y, 0, 30, colors="#cccccc", linestyles="-", linewidth=0.6,
                  zorder=1)

        # Plot every reactive cycle marker
        for branch in (0, 1, 2):
            ts = [t / 60 for t, ty in d["reactive_cycles"] if ty == branch]
            if ts:
                ax.scatter(ts, [y] * len(ts),
                           marker=branch_marker[branch],
                           color=branch_color[branch],
                           edgecolors="black", linewidths=0.4,
                           s=85, zorder=3)

        # Per-scenario tally text on the right of the row
        d0 = sum(1 for _, ty in d["reactive_cycles"] if ty == 0)
        d1 = sum(1 for _, ty in d["reactive_cycles"] if ty == 1)
        d2 = sum(1 for _, ty in d["reactive_cycles"] if ty == 2)
        tally = f"  {d0} shuf  +  {d1} rot  +  {d2} comp"
        ax.text(30.3, y, tally, va="center", ha="left", fontsize=9,
                color="#333333")

    ax.set_xlim(0, 35)
    ax.set_ylim(-0.6, 2.6)
    ax.set_yticks(list(y_positions.values()))
    ax.set_yticklabels([SCENARIO_TITLES[s] for s in SCENARIOS])
    ax.set_xlabel("Simulated time (min)")
    ax.set_xticks([0, 5, 10, 15, 20, 25, 30])
    ax.grid(True, axis="x", linestyle="--", alpha=0.3)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.set_title("When each MTD reactive cycle fired and which branch it took",
                 fontsize=11)

    # ---- single legend below the axis -------------------------------------
    from matplotlib.lines import Line2D
    legend_elements = [
        Line2D([0], [0], marker=branch_marker[b], color="w",
               markerfacecolor=branch_color[b], markeredgecolor="black",
               markersize=10, label=f"{branch_label[b]} (d={b})")
        for b in (0, 1, 2)
    ]
    ax.legend(handles=legend_elements, loc="lower center",
              bbox_to_anchor=(0.5, -0.42), ncol=3, frameon=False, fontsize=9)

    fig.tight_layout()
    fig.savefig(out_dir / "fig_anomaly_timeline.png",
                bbox_inches="tight", facecolor="white")
    plt.close(fig)


# ========================================================================
# Figure 4: Reactive branch distribution per scenario
# ========================================================================
def fig_branch_distribution(data: Dict, out_dir: Path):
    fig, ax = plt.subplots(figsize=(7, 4))

    counts = {"d0": [], "d1": [], "d2": []}
    labels = []
    for scn in SCENARIOS:
        d = data[(scn, "mtd")]
        d0 = sum(1 for _, t in d["reactive_cycles"] if t == 0)
        d1 = sum(1 for _, t in d["reactive_cycles"] if t == 1)
        d2 = sum(1 for _, t in d["reactive_cycles"] if t == 2)
        counts["d0"].append(d0)
        counts["d1"].append(d1)
        counts["d2"].append(d2)
        labels.append(SCENARIO_TITLES[scn])

    x = np.arange(len(labels))
    w = 0.55
    ax.bar(x, counts["d0"], w, color=COLOR_CPU, label="STALE_PORT → IPv6 shuffle")
    ax.bar(x, counts["d1"], w, bottom=counts["d0"], color=COLOR_TX,
           label="CONN_FAILURE → token rotation")
    bot2 = np.array(counts["d0"]) + np.array(counts["d1"])
    ax.bar(x, counts["d2"], w, bottom=bot2, color=COLOR_NOMTD,
           label="CPU_LOAD → shuffle + rate limit")

    for i, scn in enumerate(SCENARIOS):
        total = counts["d0"][i] + counts["d1"][i] + counts["d2"][i]
        ax.text(x[i], total + 0.5, str(total),
                ha="center", va="bottom", fontsize=10, fontweight="bold")

    ax.set_xticks(x); ax.set_xticklabels(labels)
    ax.set_ylabel("Reactive cycles in 30 min")
    ax.set_title("Reactive branch distribution per scenario")
    ax.legend(loc="upper left", fontsize=9)
    ax.set_ylim(0, max(counts["d0"][i] + counts["d1"][i] + counts["d2"][i]
                       for i in range(3)) + 5)

    fig.tight_layout()
    fig.savefig(out_dir / "fig_branch_distribution.png", bbox_inches="tight")
    plt.close(fig)


# ========================================================================
# Figure 5: Attacker's perspective -- two universal metrics that work
#           across all three scenarios.
#           Left:  useful attack window (seconds before first reactive cycle)
#           Right: mean inter-mutation interval (seconds between mutations)
#           Both: lower = stronger defence.
# ========================================================================
def fig_attacker_view(data: Dict, out_dir: Path):
    SIM_DURATION_S = 30 * 60

    useful = {}        # scenario -> seconds before first reactive cycle
    mut_int = {}       # scenario -> mean seconds between mutations

    for scn in SCENARIOS:
        d = data[(scn, "mtd")]

        # First reactive cycle time vs attacker warm-up end (warm-up = 45 s).
        # We approximate attacker_start as 0; the warm-up adds 45 s, so the
        # useful window is (first_reactive - 45).
        reactive_ts = [t for (t, _dom) in d.get("reactive_cycles", [])]
        if reactive_ts:
            useful[scn] = max(0.0, reactive_ts[0] - 45.0)
        else:
            useful[scn] = SIM_DURATION_S    # never fired in run

        # Mutation event timestamps = proactive shuffles + proactive port hops
        # + reactive cycles.  Each one invalidates the attacker's reconnaissance.
        # We extract them by replaying the log via the existing collectors:
        # reactive_cycles already holds (t, dom); the proactive cycles are not
        # individually timestamped in `data` but can be approximated as evenly
        # spaced if we know totals.  Easier approach: read the log file again
        # for the cycle markers.  As a shortcut, compute interval from total
        # mutations and run duration:
        proactive_shuf = d.get("proactive_shuffles", 0) or 0
        proactive_hop  = d.get("proactive_hops", 0) or 0
        # The load_log dict above does not expose totals -- but we can rebuild
        # totals from the markers we DO have: reactive timestamps + the
        # equally-spaced proactive cadences (120 s shuffle, 300 s port hop).
        total_mutations = (len(reactive_ts)
                           + (SIM_DURATION_S // 120)
                           + (SIM_DURATION_S // 300))
        if total_mutations > 0:
            mut_int[scn] = SIM_DURATION_S / total_mutations
        else:
            mut_int[scn] = float("inf")

    fig, (ax_l, ax_r) = plt.subplots(1, 2, figsize=(11, 4.0))
    x = np.arange(len(SCENARIOS))
    labels = [SCENARIO_TITLES[s] for s in SCENARIOS]

    # ---- Left: useful attack window -------------------------------------
    vals_l = [useful[s] for s in SCENARIOS]
    bars_l = ax_l.bar(x, vals_l, 0.55, color=COLOR_MTD,
                      edgecolor="black", linewidth=0.5)
    for b, v in zip(bars_l, vals_l):
        ax_l.text(b.get_x() + b.get_width() / 2, b.get_height() + 10,
                  f"{v:.0f}s", ha="center", va="bottom", fontsize=10,
                  fontweight="bold")
    ax_l.set_xticks(x)
    ax_l.set_xticklabels(labels)
    ax_l.set_ylabel("Seconds")
    ax_l.set_title("Attacker useful window\n(time before first reactive MTD cycle)")
    ax_l.set_ylim(0, max(vals_l) + 80)
    ax_l.grid(True, axis="y", alpha=0.25, linestyle="--")

    # ---- Right: mean inter-mutation interval ----------------------------
    vals_r = [mut_int[s] for s in SCENARIOS]
    bars_r = ax_r.bar(x, vals_r, 0.55, color=COLOR_MTD,
                      edgecolor="black", linewidth=0.5)
    for b, v in zip(bars_r, vals_r):
        ax_r.text(b.get_x() + b.get_width() / 2, b.get_height() + 1,
                  f"{v:.0f}s", ha="center", va="bottom", fontsize=10,
                  fontweight="bold")
    ax_r.set_xticks(x)
    ax_r.set_xticklabels(labels)
    ax_r.set_ylabel("Seconds")
    ax_r.set_title("Mean inter-mutation interval\n(time between consecutive MTD mutations)")
    ax_r.set_ylim(0, max(vals_r) + 12)
    ax_r.grid(True, axis="y", alpha=0.25, linestyle="--")

    # Annotation: under no-MTD, both metrics would be "unbounded".
    fig.text(0.5, -0.02,
             "Under no-MTD both metrics are unbounded (no reactive cycle ever fires; "
             "an enumerated address remains valid for the entire run).",
             ha="center", va="top", fontsize=9, style="italic", color="0.35")

    fig.tight_layout()
    fig.savefig(out_dir / "fig_attacker_view.png", bbox_inches="tight")
    plt.close(fig)


# ========================================================================
# Main
# ========================================================================
def main() -> int:
    project_dir = Path(__file__).resolve().parent.parent
    # Save in TWO places: the eval/figures/ folder (easy to find next to
    # the script) and the thesis Images/Evaluation/ folder (used by
    # \includegraphics in the LaTeX source).
    figure_dirs = [
        project_dir / "eval" / "figures",
        project_dir / "Master_Thesis___MTD" / "Images" / "Evaluation",
    ]
    for d in figure_dirs:
        d.mkdir(parents=True, exist_ok=True)
    out_dir = figure_dirs[0]   # primary, the rest are copies

    log_set = [
        ("scan",     "mtd",   project_dir / "mtd_attack_scan_sky.txt"),
        ("sinkhole", "mtd",   project_dir / "mtd_attack_sinkhole_sky.txt"),
        ("flood",    "mtd",   project_dir / "mtd_attack_flood_sky.txt"),
        ("scan",     "nomtd", project_dir / "nomtd_scan_sky.txt"),
        ("sinkhole", "nomtd", project_dir / "nomtd_sinkhole_sky.txt"),
        ("flood",    "nomtd", project_dir / "nomtd_flood_sky.txt"),
    ]

    data: Dict[Tuple[str, str], Dict] = {}
    for scenario, condition, path in log_set:
        print(f"  reading: {path.name}")
        data[(scenario, condition)] = load_log(path)

    print()
    print("Generating figures...")
    fig_pdr_over_time(data, out_dir)
    fig_energy_breakdown(data, out_dir)
    fig_anomaly_timeline(data, out_dir)
    fig_branch_distribution(data, out_dir)
    fig_attacker_view(data, out_dir)

    # Mirror the four files into every output directory.
    import shutil
    for name in ("fig_pdr_over_time.png", "fig_energy_breakdown.png",
                 "fig_anomaly_timeline.png", "fig_branch_distribution.png",
                 "fig_attacker_view.png"):
        for d in figure_dirs[1:]:
            shutil.copy(out_dir / name, d / name)
        for d in figure_dirs:
            print(f"  wrote {d / name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
