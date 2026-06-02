#!/usr/bin/env python3
"""
aggregate_seeds.py

Walks all 30 *_run[1-5].txt logs through parse_logs.parse_log(), computes
mean and stdev of each metric per (scenario, condition).  Writes a
machine-readable results_5seed.json AND a human-readable console table.

A seed whose log did not reach 28:00 simulated time is FLAGGED (its data
is still included but the warning is printed so we can decide whether to
drop it from the per-cell aggregate).
"""
from __future__ import annotations
import sys, json, statistics
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from parse_logs import parse_log, RunResult

SEEDS = [1, 2, 3, 4, 5]   # logical seed indices (file suffix run1..run5)
SEED_NUMBERS = {           # documentation only -- the actual randomseed used in each .csc
    1: 123456, 2: 687681, 3: 956978, 4: 835700, 5: 371491,
}
SCENARIOS = [("scan","mtd"), ("scan","nomtd"),
             ("sinkhole","mtd"), ("sinkhole","nomtd"),
             ("flood","mtd"), ("flood","nomtd")]

def log_path(project_dir, scenario, condition, seed):
    if condition == "mtd":
        return project_dir / f"mtd_attack_{scenario}_sky_run{seed}.txt"
    else:
        return project_dir / f"nomtd_{scenario}_sky_run{seed}.txt"

def get_last_ts(path):
    """Last simulated time observed in the log (best-effort)."""
    import re
    TS = re.compile(r"^(\d+):(\d+)\.(\d+)\s+ID:")
    last = 0.0
    try:
        with open(path, encoding="utf-8", errors="replace") as fp:
            for line in fp:
                m = TS.match(line)
                if m:
                    last = int(m.group(1)) * 60 + int(m.group(2)) + int(m.group(3)) / 1000.0
    except FileNotFoundError:
        return None
    return last

def main():
    project_dir = Path(__file__).resolve().parent.parent

    # collect: results[(scenario, condition)] = list of RunResult, one per seed
    results = {sc: [] for sc in SCENARIOS}
    short_runs = []   # (label, last_ts) for seeds that did not reach 28:00

    for seed in SEEDS:
        for (scn, cond) in SCENARIOS:
            p = log_path(project_dir, scn, cond, seed)
            if not p.exists():
                print(f"[MISS] {p.name}", file=sys.stderr)
                continue
            last_ts = get_last_ts(p)
            if last_ts is not None and last_ts < 28 * 60:
                short_runs.append((p.name, last_ts))
            r = parse_log(p, scn, cond)
            results[(scn, cond)].append(r)

    print()
    print("=== Short-run warning (< 28:00 simulated time) ===")
    if short_runs:
        for name, ts in short_runs:
            mm = int(ts // 60); ss = ts - 60*mm
            print(f"  {name:50s}  ended at {mm:02d}:{ss:05.2f}")
    else:
        print("  None.  All logs reached >= 28:00.")
    print()

    # metrics we care about per RunResult
    METRICS = [
        ("br_rx_total",        "%9.1f"),
        ("legit_rx_total",     "%9.1f"),
        ("legit_anom_total",   "%9.1f"),
        ("att_rx_total",       "%9.1f"),
        ("reactive_cycles",    "%6.1f"),
        ("dominant_0",         "%5.1f"),
        ("dominant_1",         "%5.1f"),
        ("dominant_2",         "%5.1f"),
        ("silence_events",     "%6.1f"),
        ("rate_limit_drops",   "%7.1f"),
        ("anomaly_warns",      "%7.1f"),
        ("attacker_packets_sent", "%8.1f"),
    ]

    agg = {}
    print("=== Aggregated 5-seed means (mean +/- stdev) ===")
    print(f"{'scenario':>9s}  {'cond':>5s}  {'n':>2s}  " + "  ".join(f"{m[:11]:>12s}" for m,_ in METRICS))
    for (scn, cond) in SCENARIOS:
        rows = results[(scn, cond)]
        if not rows: continue
        n = len(rows)
        cell = {"n": n}
        line = f"{scn:>9s}  {cond:>5s}  {n:>2d}  "
        for metric, fmt in METRICS:
            vals = [getattr(r, metric) for r in rows]
            m = statistics.mean(vals)
            s = statistics.stdev(vals) if n >= 2 else 0.0
            cell[metric] = {"mean": m, "stdev": s, "values": vals}
            line += f"{m:>5.0f}+/-{s:<4.0f}  "
        agg[f"{scn}_{cond}"] = cell
        print(line)

    # Derived computations the chapter cares about
    # PDR-legit = legit_rx / expected (29*180=5220) per run, then aggregate
    print()
    print("=== Derived per-seed metrics: effective legit PDR and attacker delivery ===")
    EXPECTED = 29 * 180  # 5220
    derived = {}
    for (scn, cond) in SCENARIOS:
        rows = results[(scn, cond)]
        if not rows: continue
        pdr = [(r.legit_rx_total - r.legit_anom_total) / EXPECTED * 100 for r in rows]
        # attacker delivery only meaningful for flood (ar > 0 in others is 0)
        deliv = []
        for r in rows:
            if r.attacker_packets_sent > 0:
                deliv.append(r.att_rx_total / r.attacker_packets_sent * 100)
            else:
                deliv.append(0.0)
        derived[f"{scn}_{cond}"] = {
            "effective_legit_pdr_pct": {
                "mean": statistics.mean(pdr),
                "stdev": statistics.stdev(pdr) if len(pdr) >= 2 else 0.0,
                "values": pdr,
            },
            "attacker_delivery_pct": {
                "mean": statistics.mean(deliv),
                "stdev": statistics.stdev(deliv) if len(deliv) >= 2 else 0.0,
                "values": deliv,
            },
        }
        m_pdr = derived[f"{scn}_{cond}"]["effective_legit_pdr_pct"]
        m_del = derived[f"{scn}_{cond}"]["attacker_delivery_pct"]
        print(f"  {scn:>9s} {cond:>5s}  PDR_eff={m_pdr['mean']:5.1f}+/-{m_pdr['stdev']:4.1f}%  "
              f"atk_deliv={m_del['mean']:5.1f}+/-{m_del['stdev']:4.1f}%")

    out = {"seeds": SEED_NUMBERS, "short_runs": short_runs,
           "aggregated": agg, "derived": derived}
    outp = project_dir / "eval" / "results_5seed.json"
    outp.write_text(json.dumps(out, indent=2, default=float))
    print(f"\nWrote {outp}")

if __name__ == "__main__":
    main()
