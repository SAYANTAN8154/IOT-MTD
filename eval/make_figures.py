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
    "savefig.dpi":        150,
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
        "br_metrics_pts":    [],   # list of (t_sec, rx, anom, lr, la, ar, aa)
        "anomaly_events":    [],   # list of (t_sec, type)
        "silence_events":    [],   # list of t_sec
        "reactive_cycles":   [],   # list of (t_sec, dominant)
        "rate_limit_drops":  [],   # list of t_sec
        "proactive_shuffles": 0,
        "proactive_hops":    0,
        "mtd_disabled":      False,
        "br_energest_last":  None, # (cpu, lpm, tx, rx)
        "sensor_energest":   {},   # node_id -> (cpu, lpm, tx, rx) last
    }

    if not path.exists():
        return out

    SIM_DURATION_S = 30 * 60   # 30 min, with 30s slack matching parse_logs.py
    with path.open(encoding="utf-8", errors="replace") as fp:
        for raw in fp:
            line = raw.rstrip()
            t = parse_ts(line)
            if t is None:
                continue
            if t > SIM_DURATION_S + 30:
                break

            if "MTD orchestrator DISABLED" in line:
                out["mtd_disabled"] = True

            # Modern BR_METRICS format: rx=N anom=N lr=N la=N ar=N aa=N
            m = re.search(
                r"BR_METRICS rx=(\d+) anom=(\d+) lr=(\d+) la=(\d+) ar=(\d+) aa=(\d+)",
                line)
            if m:
                out["br_metrics_pts"].append(
                    (t, int(m.group(1)), int(m.group(2)),
                     int(m.group(3)), int(m.group(4)),
                     int(m.group(5)), int(m.group(6))))
            else:
                # Legacy format (older logs): rx=N anomalous=N
                m = re.search(r"BR_METRICS rx=(\d+) anomalous=(\d+)", line)
                if m:
                    out["br_metrics_pts"].append(
                        (t, int(m.group(1)), int(m.group(2)),
                         0, 0, 0, 0))

            if "MTD Shuffle Cycle" in line:
                out["proactive_shuffles"] += 1
            if "=== MTD Port Hop" in line:
                out["proactive_hops"] += 1

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
    """
    Cumulative BR ingestion over the 30-min run, MTD vs no-MTD, with
    mean +/- stdev across the 5-seed campaign shown as a shaded band.
    """
    project_dir = Path(__file__).resolve().parent.parent
    SEEDS = [1, 2, 3, 4, 5]
    SNAPSHOTS_MIN = [5, 10, 15, 20, 25, 30]   # the 5-min BR_METRICS marks

    fig, axes = plt.subplots(1, 3, figsize=(11, 3.6), sharey=False)

    def collect(scn, cond):
        # Returns per-snapshot list of rx values across seeds: [n_snapshots][n_seeds]
        prefix = "mtd_attack_" if cond == "mtd" else "nomtd_"
        per_seed_curves = []
        for seed in SEEDS:
            pp = project_dir / f"{prefix}{scn}_sky_run{seed}.txt"
            if not pp.exists():
                continue
            d = load_log(pp)
            # Snap each BR_METRICS point to its nearest minute mark.
            by_min = {}
            for pt in d["br_metrics_pts"]:
                t, rx = pt[0], pt[1]
                mm = round(t / 60)
                if mm in SNAPSHOTS_MIN:
                    by_min[mm] = rx
            curve = [by_min.get(mm, np.nan) for mm in SNAPSHOTS_MIN]
            per_seed_curves.append(curve)
        if not per_seed_curves:
            return None
        arr = np.array(per_seed_curves, dtype=float)
        mean = np.nanmean(arr, axis=0)
        std  = np.nanstd(arr, axis=0, ddof=1) if arr.shape[0] >= 2 else np.zeros(len(SNAPSHOTS_MIN))
        return mean, std

    for ax, scn in zip(axes, SCENARIOS):
        for cond, color, label in (("mtd", COLOR_MTD, "MTD"),
                                   ("nomtd", COLOR_NOMTD, "no-MTD")):
            res = collect(scn, cond)
            if res is None:
                continue
            mean, std = res
            ax.plot(SNAPSHOTS_MIN, mean, marker="o", color=color,
                    label=label, linewidth=1.6)
            ax.fill_between(SNAPSHOTS_MIN, mean - std, mean + std,
                            color=color, alpha=0.18, linewidth=0)
        ax.set_title(SCENARIO_TITLES[scn])
        ax.set_xlabel("Simulated time (min)")
        ax.set_ylabel("Cumulative BR ingestion (packets)")
        ax.legend(loc="upper left", fontsize=9)

    fig.suptitle("Mean $\\pm$ stdev across the 5-seed campaign (n=5 per snapshot)",
                 fontsize=10, y=1.02)
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
    # 5-seed mean +/- stdev per state, computed by loading all 30 logs.
    project_dir = Path(__file__).resolve().parent.parent
    SEEDS = [1, 2, 3, 4, 5]
    states = ["CPU", "LPM", "TX", "RX"]
    state_colors = [COLOR_CPU, COLOR_LPM, COLOR_TX, COLOR_RX]

    # rows[state][cell] = mean; errs[state][cell] = stdev
    n_cells = len(SCENARIOS) * 2
    sensor_means = [[0.0]*n_cells for _ in states]
    sensor_errs  = [[0.0]*n_cells for _ in states]
    br_means     = [[0.0]*n_cells for _ in states]
    br_errs      = [[0.0]*n_cells for _ in states]
    col_labels = []
    col_idx = 0
    for scn in SCENARIOS:
        for cond in ("mtd", "nomtd"):
            col_labels.append(f"{SCENARIO_TITLES[scn]}\n{cond.upper()}")
            sensor_per_state_seeds = [[] for _ in states]
            br_per_state_seeds     = [[] for _ in states]
            prefix = "mtd_attack_" if cond == "mtd" else "nomtd_"
            for seed in SEEDS:
                pp = project_dir / f"{prefix}{scn}_sky_run{seed}.txt"
                if not pp.exists(): continue
                d = load_log(pp)
                if d["sensor_energest"]:
                    vals = list(d["sensor_energest"].values())
                    cpu_mean = float(np.mean([v[0] for v in vals]))
                    lpm_mean = float(np.mean([v[1] for v in vals]))
                    tx_mean  = float(np.mean([v[2] for v in vals]))
                    rx_mean  = float(np.mean([v[3] for v in vals]))
                    e = energy_split_mj(cpu_mean, lpm_mean, tx_mean, rx_mean)
                    for k in range(4): sensor_per_state_seeds[k].append(e[k])
                if d["br_energest_last"]:
                    e = energy_split_mj(*d["br_energest_last"])
                    for k in range(4): br_per_state_seeds[k].append(e[k])
            for k in range(4):
                if sensor_per_state_seeds[k]:
                    sensor_means[k][col_idx] = float(np.mean(sensor_per_state_seeds[k]))
                    sensor_errs[k][col_idx]  = float(np.std(sensor_per_state_seeds[k], ddof=1)) if len(sensor_per_state_seeds[k]) >= 2 else 0.0
                if br_per_state_seeds[k]:
                    br_means[k][col_idx] = float(np.mean(br_per_state_seeds[k]))
                    br_errs[k][col_idx]  = float(np.std(br_per_state_seeds[k], ddof=1)) if len(br_per_state_seeds[k]) >= 2 else 0.0
            col_idx += 1

    fig, (ax_sensor, ax_br) = plt.subplots(1, 2, figsize=(13, 4.6))

    def _grouped(ax, mean_rows, err_rows, title, ylabel):
        n_states = len(states)
        bar_w    = 0.18
        x        = np.arange(n_cells)
        for i, (state, color, means, errs) in enumerate(zip(states, state_colors, mean_rows, err_rows)):
            offset = (i - (n_states - 1) / 2) * bar_w
            # Clamp tiny means so they show on log scale
            mvals = [max(m, 1) for m in means]
            ax.bar(x + offset, mvals, bar_w, yerr=errs, capsize=2,
                   color=color, label=state,
                   edgecolor="black", linewidth=0.4,
                   error_kw={"elinewidth": 0.7, "ecolor": "#333"})
        ax.set_yscale("log")
        ax.set_ylim(bottom=1)
        ax.set_xticks(x)
        ax.set_xticklabels(col_labels, fontsize=8)
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.grid(True, which="both", axis="y", alpha=0.25, linestyle="--")

    _grouped(ax_sensor, sensor_means, sensor_errs,
             "Mean per-sensor energy (29 nodes, n=5 seeds)",
             "Energy (mJ, 30 min)  [log scale]")
    _grouped(ax_br, br_means, br_errs,
             "Border router energy (n=5 seeds)",
             "Energy (mJ, 30 min)  [log scale]")

    # Single shared legend across the top of both panels.
    handles, labels = ax_sensor.get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=4, fontsize=9,
               framealpha=0.9, bbox_to_anchor=(0.5, 1.03))

    fig.tight_layout(rect=[0, 0, 1, 0.94])
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
    """
    Single-run reactive-cycle timeline (seed=1 / run1).
    One row per scenario; markers identify the branch each cycle fired.
    A multi-seed version was tried (one row per (scenario, seed)) but was
    visually too dense; the per-scenario branch counts and their seed-to-
    seed spread are reported as means in tab:branches and visually in
    fig_branch_distribution, so this figure is intentionally a single
    representative trace.
    """
    project_dir = Path(__file__).resolve().parent.parent
    branch_color  = {0: "#1f4e79", 1: "#ed7d31", 2: "#c00000"}
    branch_marker = {0: "v",       1: "s",       2: "D"}
    branch_label  = {0: "shuffle", 1: "token rotation", 2: "shuffle + rate limit"}

    fig, ax = plt.subplots(figsize=(11, 3.6))
    y_positions = {scn: 2 - i for i, scn in enumerate(SCENARIOS)}

    for scn in SCENARIOS:
        y = y_positions[scn]
        pp = project_dir / f"mtd_attack_{scn}_sky_run1.txt"
        d = load_log(pp) if pp.exists() else data[(scn, "mtd")]

        ax.hlines(y, 0, 30, colors="#cccccc", linestyles="-", linewidth=0.6,
                  zorder=1)
        for branch in (0, 1, 2):
            ts = [t / 60 for t, ty in d["reactive_cycles"] if ty == branch]
            if ts:
                ax.scatter(ts, [y] * len(ts),
                           marker=branch_marker[branch],
                           color=branch_color[branch],
                           edgecolors="black", linewidths=0.4,
                           s=85, zorder=3)

        d0 = sum(1 for _, ty in d["reactive_cycles"] if ty == 0)
        d1 = sum(1 for _, ty in d["reactive_cycles"] if ty == 1)
        d2 = sum(1 for _, ty in d["reactive_cycles"] if ty == 2)
        tally = f"  {d0} shuf  +  {d1} rot  +  {d2} comp"
        ax.text(30.3, y, tally, va="center", ha="left", fontsize=9, color="#333333")

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
    ax.set_title("When each MTD reactive cycle fired (seed=1 / run1, single representative trace)",
                 fontsize=11)

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
    """
    Grouped (not stacked) bars per branch, averaged across the 5-seed
    campaign with stdev error bars.  Reads all *_run[1-5].txt logs
    directly so the figure does not depend on the single-log `data`
    dict that the other figures use.
    """
    project_dir = Path(__file__).resolve().parent.parent

    # Means and stdevs per scenario, per branch
    means  = {scn: [0.0, 0.0, 0.0] for scn in SCENARIOS}
    stdevs = {scn: [0.0, 0.0, 0.0] for scn in SCENARIOS}
    totals_mean = {scn: 0.0 for scn in SCENARIOS}

    for scn in SCENARIOS:
        per_seed = [[], [], []]   # one list per branch (d0, d1, d2)
        per_seed_total = []
        for seed in (1, 2, 3, 4, 5):
            p = project_dir / f"mtd_attack_{scn}_sky_run{seed}.txt"
            if not p.exists():
                continue
            d = load_log(p)
            counts = [0, 0, 0]
            for _, t in d["reactive_cycles"]:
                if 0 <= t <= 2:
                    counts[t] += 1
            for b in range(3):
                per_seed[b].append(counts[b])
            per_seed_total.append(sum(counts))
        for b in range(3):
            if per_seed[b]:
                means[scn][b]  = float(np.mean(per_seed[b]))
                stdevs[scn][b] = float(np.std(per_seed[b], ddof=1)) if len(per_seed[b]) > 1 else 0.0
        if per_seed_total:
            totals_mean[scn] = float(np.mean(per_seed_total))

    branch_labels = ["STALE_PORT → IPv6 shuffle",
                     "CONN_FAILURE → token rotation",
                     "CPU_LOAD → shuffle + rate limit"]
    branch_colors = [COLOR_CPU, COLOR_TX, COLOR_NOMTD]

    fig, ax = plt.subplots(figsize=(8, 4.2))
    x = np.arange(len(SCENARIOS))
    bar_w = 0.25

    for b in range(3):
        bar_means  = [means[scn][b]  for scn in SCENARIOS]
        bar_stdevs = [stdevs[scn][b] for scn in SCENARIOS]
        offset = (b - 1) * bar_w
        bars = ax.bar(x + offset, bar_means, bar_w,
                      yerr=bar_stdevs, capsize=3,
                      color=branch_colors[b], edgecolor="black", linewidth=0.5,
                      label=branch_labels[b],
                      error_kw={"elinewidth": 0.8, "ecolor": "black"})
        # Annotate non-zero bars with the mean (rounded to 1 decimal)
        for bar, m in zip(bars, bar_means):
            if m >= 0.5:
                ax.text(bar.get_x() + bar.get_width() / 2, m + 0.4,
                        f"{m:.1f}", ha="center", va="bottom",
                        fontsize=8.5, color="black")

    # Per-scenario total cycle count annotation (well above the cluster)
    ymax_per_group = [max(m + s for m, s in zip(means[scn], stdevs[scn])) for scn in SCENARIOS]
    cluster_top = max(ymax_per_group) + 5
    for i, scn in enumerate(SCENARIOS):
        ax.text(x[i], cluster_top, f"total {totals_mean[scn]:.0f}",
                ha="center", va="bottom", fontsize=10, fontweight="bold",
                color="#333333")

    ax.set_xticks(x)
    ax.set_xticklabels([SCENARIO_TITLES[s] for s in SCENARIOS])
    ax.set_ylabel("Reactive cycles in 30 min (mean ± stdev, n=5)")
    ax.set_title("Reactive branch distribution per scenario")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=3,
              fontsize=9, frameon=False)
    ax.set_ylim(0, cluster_top + 4)
    ax.grid(True, axis="y", alpha=0.25, linestyle="--")
    ax.set_axisbelow(True)

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
    project_dir = Path(__file__).resolve().parent.parent
    SEEDS = [1, 2, 3, 4, 5]
    SIM_DURATION_S = 30 * 60

    # Published aggregated 5-seed values from the Evaluation chapter
    # (Table: "Universal attacker-side metrics"). Hard-coded here so the
    # figure is guaranteed to match the table -- both derive from the same
    # 30-run aggregation. mut_int stdev is propagated from the mutation-count
    # stdev as 1800/M^2 * sigma_M.
    PUBLISHED = {
        "scan":     {"useful": (331.2, 211.6), "mut_int": (53.3, 3.6)},
        "sinkhole": {"useful": (568.6,  38.1), "mut_int": (59.6, 1.6)},
        "flood":    {"useful": (  5.0,   0.2), "mut_int": (46.4, 1.9)},
    }

    fig, (ax_l, ax_r) = plt.subplots(1, 2, figsize=(11, 4.0))
    x = np.arange(len(SCENARIOS))
    labels = [SCENARIO_TITLES[s] for s in SCENARIOS]

    # Left: useful window
    useful_m = [PUBLISHED[s]["useful"][0] for s in SCENARIOS]
    useful_s = [PUBLISHED[s]["useful"][1] for s in SCENARIOS]
    bars_l = ax_l.bar(x, useful_m, 0.55, yerr=useful_s, capsize=4,
                      color=COLOR_MTD, edgecolor="black", linewidth=0.5,
                      error_kw={"elinewidth": 0.9, "ecolor": "black"})
    for bar, m, s in zip(bars_l, useful_m, useful_s):
        ax_l.text(bar.get_x() + bar.get_width() / 2, m + s + 15,
                  f"{m:.0f}$\\pm${s:.0f}s", ha="center", va="bottom",
                  fontsize=10, fontweight="bold")
    ax_l.set_xticks(x); ax_l.set_xticklabels(labels)
    ax_l.set_ylabel("Seconds")
    ax_l.set_title("MTTSF proxy\n(time before first reactive MTD cycle, n=5)")
    ax_l.set_ylim(0, max(m + s for m, s in zip(useful_m, useful_s)) + 120)
    ax_l.grid(True, axis="y", alpha=0.25, linestyle="--")

    # Right: mean inter-mutation
    mi_m = [PUBLISHED[s]["mut_int"][0] for s in SCENARIOS]
    mi_s = [PUBLISHED[s]["mut_int"][1] for s in SCENARIOS]
    bars_r = ax_r.bar(x, mi_m, 0.55, yerr=mi_s, capsize=4,
                      color=COLOR_MTD, edgecolor="black", linewidth=0.5,
                      error_kw={"elinewidth": 0.9, "ecolor": "black"})
    for bar, m, s in zip(bars_r, mi_m, mi_s):
        ax_r.text(bar.get_x() + bar.get_width() / 2, m + s + 1.5,
                  f"{m:.1f}$\\pm${s:.1f}s", ha="center", va="bottom",
                  fontsize=10, fontweight="bold")
    ax_r.set_xticks(x); ax_r.set_xticklabels(labels)
    ax_r.set_ylabel("Seconds")
    ax_r.set_title("Mean inter-mutation interval\n(time between consecutive MTD mutations, n=5)")
    ax_r.set_ylim(0, max(m + s for m, s in zip(mi_m, mi_s)) + 15)
    ax_r.grid(True, axis="y", alpha=0.25, linestyle="--")

    fig.text(0.5, -0.02,
             "Under no-MTD both metrics are unbounded (no reactive cycle ever fires; "
             "an enumerated address remains valid for the entire run).",
             ha="center", va="top", fontsize=9, style="italic", color="0.35")

    fig.tight_layout()
    fig.savefig(out_dir / "fig_attacker_view.png", bbox_inches="tight")
    plt.close(fig)


# ========================================================================
# Figure 6: Flood attacker delivery -- MTD vs no-MTD headline result
# ========================================================================
def fig_flood_delivery(_data: Dict, out_dir: Path):
    """
    Headline flood security result: attacker delivery rate with MTD
    enabled vs no-MTD, with 5-seed error bars.
    """
    project_dir = Path(__file__).resolve().parent.parent
    SEEDS = [1, 2, 3, 4, 5]

    def aggregate(prefix):
        atk = []
        for seed in SEEDS:
            pp = project_dir / f"{prefix}flood_sky_run{seed}.txt"
            if not pp.exists(): continue
            d = load_log(pp)
            inj = d.get("attacker_packets_sent", 0)
            if not d["br_metrics_pts"]:
                continue
            # Use per-source counters: (t, rx, anom, lr, la, ar, aa)
            _, _, _, _lr, _la, ar, _ = d["br_metrics_pts"][-1]
            if inj > 0:
                atk.append(ar / inj * 100)
        return atk

    atk_mtd = aggregate("mtd_attack_")
    atk_no  = aggregate("nomtd_")

    def ms(v):
        if not v: return (0.0, 0.0)
        return float(np.mean(v)), float(np.std(v, ddof=1)) if len(v) >= 2 else 0.0

    am_no,  as_no  = ms(atk_no)
    am_mtd, as_mtd = ms(atk_mtd)

    fig, ax = plt.subplots(figsize=(5.5, 4.0))
    x = np.arange(2)
    labels = ["no MTD", "MTD enabled"]
    bars = ax.bar(x, [am_no, am_mtd], 0.5,
                  yerr=[as_no, as_mtd], capsize=4,
                  color=[COLOR_NOMTD, COLOR_MTD], edgecolor="black", linewidth=0.5,
                  error_kw={"elinewidth": 0.9, "ecolor": "black"})
    for bar, m, s in zip(bars, [am_no, am_mtd], [as_no, as_mtd]):
        ax.text(bar.get_x() + bar.get_width()/2, m + s + 2,
                f"{m:.1f}$\\pm${s:.1f}%", ha="center", va="bottom",
                fontsize=10, fontweight="bold")

    ax.set_xticks(x); ax.set_xticklabels(labels)
    ax.set_ylabel("Attacker delivery rate (%)")
    ax.set_ylim(0, 100)
    ax.set_title("Flood scenario: attacker delivery rate\n"
                 "(mean $\\pm$ stdev across 5 seeds)")
    ax.grid(True, axis="y", alpha=0.25, linestyle="--")
    ax.set_axisbelow(True)

    fig.tight_layout()
    fig.savefig(out_dir / "fig_flood_delivery.png", bbox_inches="tight")
    plt.close(fig)


# ========================================================================
# Figure 7: Attacker-speed sweep -- branch composition at 2/10/50 pkt/s
# ========================================================================
def fig_speed_sweep(_data: Dict, out_dir: Path):
    """
    How the scan-scenario branch distribution shifts with attacker rate.
    Three rate groups (2 / 10 / 50 pkt/s), each with the d0/d1/d2 split
    as grouped bars.  Visualises the table:variance_speed result.
    """
    project_dir = Path(__file__).resolve().parent.parent
    rates = [
        ("2 pkt/s\n(slow)",      "mtd_attack_scan_slow_sky.txt"),
        ("10 pkt/s\n(baseline)", "mtd_attack_scan_sky_run1.txt"),
        ("50 pkt/s\n(fast)",     "mtd_attack_scan_fast_sky.txt"),
    ]
    counts = []
    for _, fn in rates:
        pp = project_dir / fn
        d = load_log(pp) if pp.exists() else {"reactive_cycles": []}
        c = [0, 0, 0]
        for _, ty in d["reactive_cycles"]:
            if 0 <= ty <= 2: c[ty] += 1
        counts.append(c)

    branch_labels = ["STALE_PORT → IPv6 shuffle",
                     "CONN_FAILURE → token rotation",
                     "CPU_LOAD → shuffle + rate limit"]
    branch_colors = [COLOR_CPU, COLOR_TX, COLOR_NOMTD]

    fig, ax = plt.subplots(figsize=(8.5, 4.2))
    x = np.arange(len(rates))
    bar_w = 0.25

    for b in range(3):
        vals = [c[b] for c in counts]
        offset = (b - 1) * bar_w
        bars = ax.bar(x + offset, vals, bar_w,
                      color=branch_colors[b], edgecolor="black", linewidth=0.5,
                      label=branch_labels[b])
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width()/2, v + 0.3,
                        f"{v}", ha="center", va="bottom", fontsize=8.5)

    # Total above each cluster
    for i, c in enumerate(counts):
        total = sum(c)
        ax.text(x[i], max(c) + 3, f"total {total}",
                ha="center", va="bottom", fontsize=10, fontweight="bold",
                color="#333")

    ax.set_xticks(x); ax.set_xticklabels([r[0] for r in rates])
    ax.set_ylabel("Reactive cycles in 30 min")
    ax.set_ylim(0, max(max(c) for c in counts) + 7)
    ax.set_title("Scan attacker-rate sweep: branch composition at 2 / 10 / 50 pkt/s")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=3,
              fontsize=9, frameon=False)
    ax.grid(True, axis="y", alpha=0.25, linestyle="--")
    ax.set_axisbelow(True)

    fig.tight_layout()
    fig.savefig(out_dir / "fig_speed_sweep.png", bbox_inches="tight")
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
    fig_flood_delivery(data, out_dir)
    fig_speed_sweep(data, out_dir)

    # Mirror all files into every output directory.
    import shutil
    for name in ("fig_pdr_over_time.png", "fig_energy_breakdown.png",
                 "fig_anomaly_timeline.png", "fig_branch_distribution.png",
                 "fig_attacker_view.png",
                 "fig_flood_delivery.png", "fig_speed_sweep.png"):
        for d in figure_dirs[1:]:
            shutil.copy(out_dir / name, d / name)
        for d in figure_dirs:
            print(f"  wrote {d / name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
