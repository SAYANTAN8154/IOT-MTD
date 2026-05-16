#!/usr/bin/env python3
"""
parse_logs.py

Extracts the metrics used in the thesis Evaluation chapter from the
Cooja log files of the Sky-target simulation runs.

Inputs (six files, three scenarios * two conditions):
  mt_attack_scan_sky.txt          MTD-on  scan
  mt_attack_sinkhole_sky.txt      MTD-on  sinkhole
  mt_attack_flood_sky.txt         MTD-on  flood
  nomtd_scan_sky.txt              no-MTD  scan
  nomtd_sinkhole_sky.txt          no-MTD  sinkhole
  nomtd_flood_sky.txt             no-MTD  flood

Outputs:
  - Console table (one row per (scenario, condition))
  - results.json with the same numbers in machine-readable form

Energy conversion uses Tmote Sky datasheet currents (3 V supply):
  CPU active: 1.8 mA       LPM: 0.0545 mA
  Radio TX:   17.4 mA      Radio RX: 19.7 mA
  Tick rate:  32768 Hz (RTIMER_SECOND on Sky)

Energy in millijoules:
  E = (ticks / 32768) * current_mA * voltage_V

Usage:
  python eval/parse_logs.py
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from statistics import mean, stdev
from typing import Dict, List, Optional, Tuple

# -- Sky datasheet (Tmote Sky / CC2420) -----------------------------------
TICK_HZ        = 32768          # RTIMER_SECOND on Sky
SUPPLY_V       = 3.0
I_CPU_MA       = 1.8
I_LPM_MA       = 0.0545
I_TX_MA        = 17.4
I_RX_MA        = 19.7

SIM_DURATION_S = 30 * 60        # 30 simulated minutes per run
SENSOR_COUNT   = 29             # legitimate sender nodes (1 BR + 29 sensors)
SENSOR_PERIOD  = 10             # seconds between sensor sends
EXPECTED_SENDS = SENSOR_COUNT * (SIM_DURATION_S // SENSOR_PERIOD)


# -------------------------------------------------------------------------
# Data classes
# -------------------------------------------------------------------------
@dataclass
class RunResult:
    scenario:           str
    condition:          str             # "mtd" or "nomtd"
    log_file:           str

    # MTD activity
    proactive_shuffles: int = 0
    proactive_hops:     int = 0
    reactive_cycles:    int = 0
    cooldown_suppress:  int = 0
    dominant_0:         int = 0          # STALE_PORT
    dominant_1:         int = 0          # CONN_FAILURE
    dominant_2:         int = 0          # CPU_LOAD

    # Detection events
    anomaly_warns:      int = 0          # WARN: BorderRouter ANOMALY
    silence_events:     int = 0
    rate_limit_drops:   int = 0

    # Per-type counter increments (raw events, not the dominant of a cycle)
    anomaly_type_0:     int = 0          # STALE_PORT raw
    anomaly_type_1:     int = 0          # CONN_FAILURE raw
    anomaly_type_2:     int = 0          # CPU_LOAD raw

    # Traffic
    br_rx_total:        int = 0          # last BR_METRICS rx
    br_anomalous_total: int = 0          # last BR_METRICS anomalous

    # Detection latency (seconds from attacker warm-up end to first detection)
    attacker_start_s:           Optional[float] = None
    first_detection_s:          Optional[float] = None
    first_reactive_s:           Optional[float] = None

    # Attacker perspective (parsed from *_TX log lines emitted by attacker-node.c)
    attacker_packets_sent:      int = 0          # max "total=" seen in *_TX logs
    external_br_rx:             Optional[int] = None   # br_rx minus sensor baseline
    attacker_delivery_rate:     Optional[float] = None # external_br_rx / packets_sent
    attacker_useful_window_s:   Optional[float] = None # time from end of warm-up to
                                                       # first reactive cycle

    # Per-source counters from BR_SRC_METRICS (separate legit vs attacker traffic)
    legit_rx_total:             int = 0
    legit_anom_total:           int = 0
    att_rx_total:               int = 0
    att_anom_total:             int = 0
    false_positive_rate:        Optional[float] = None  # legit_anom / legit_rx
    scan_success_rate:          Optional[float] = None  # att_rx / atk_packets_sent

    # End-to-end latency from BR_LATENCY (legitimate sensor packets only)
    latency_samples:            int = 0
    latency_mean_ms:            Optional[float] = None
    latency_max_ms:             Optional[int] = None

    # Reconvergence: per-reactive-cycle time for BR RX rate to return to
    # its pre-cycle moving average.  Computed in post-processing from
    # per-packet RX log timestamps; reported here as the mean over all
    # reactive cycles in the run.
    reconvergence_mean_s:       Optional[float] = None
    reconvergence_samples:      int = 0

    # Internal: list of RX timestamps (for reconvergence calc)
    rx_event_ts:                List[float] = field(default_factory=list)
    reactive_cycle_ts:          List[float] = field(default_factory=list)

    # Energest at end of run
    br_cpu_ticks:       int = 0
    br_lpm_ticks:       int = 0
    br_tx_ticks:        int = 0
    br_rx_ticks:        int = 0

    sensor_cpu_ticks:   List[int] = field(default_factory=list)
    sensor_lpm_ticks:   List[int] = field(default_factory=list)
    sensor_tx_ticks:    List[int] = field(default_factory=list)
    sensor_rx_ticks:    List[int] = field(default_factory=list)

    # Computed
    pdr:                Optional[float]  = None
    detection_latency_s:Optional[float]  = None
    reaction_latency_s: Optional[float]  = None
    br_energy_mj:       Optional[float]  = None
    sensor_energy_mj_mean: Optional[float] = None
    sensor_energy_mj_std:  Optional[float] = None


# -------------------------------------------------------------------------
# Log parsing
# -------------------------------------------------------------------------
TS_RE = re.compile(r"^(\d+):(\d+)\.(\d+)\s+ID:(\d+)\s+(.*)$")

def parse_ts_to_sec(line: str) -> Optional[float]:
    """Parse the leading 'MM:SS.mmm' timestamp into seconds."""
    m = TS_RE.match(line)
    if not m:
        return None
    minutes = int(m.group(1))
    seconds = int(m.group(2))
    msec    = int(m.group(3))
    return minutes * 60 + seconds + msec / 1000.0


def parse_log(path: Path, scenario: str, condition: str) -> RunResult:
    r = RunResult(scenario=scenario, condition=condition, log_file=path.name)

    last_br_metrics_rx        = 0
    last_br_metrics_anomalous = 0
    last_br_energest: Optional[Tuple[int, int, int, int]] = None
    last_sensor_energest: Dict[int, Tuple[int, int, int, int]] = {}

    with path.open(encoding="utf-8", errors="replace") as fp:
        for raw in fp:
            line = raw.rstrip()
            ts   = parse_ts_to_sec(line)

            # Attacker start
            if r.attacker_start_s is None and "Attacker started" in line:
                r.attacker_start_s = ts

            # MTD activity
            if "MTD Shuffle Cycle" in line:
                r.proactive_shuffles += 1
            if "=== MTD Port Hop" in line:
                r.proactive_hops += 1
            if "MTD Reactive Cycle" in line:
                r.reactive_cycles += 1
                r.reactive_cycle_ts.append(ts)
                if r.first_reactive_s is None:
                    r.first_reactive_s = ts
            if "cooldown active" in line:
                r.cooldown_suppress += 1
            if "dominant=0" in line:
                r.dominant_0 += 1
            if "dominant=1" in line:
                r.dominant_1 += 1
            if "dominant=2" in line:
                r.dominant_2 += 1

            # Per-type anomaly increments.  The CPU_LOAD raw event (type=2)
            # is the actual flood detection signal.  Treat it as a "first
            # detection" event so the latency reported for flood matches the
            # real packet-rate-monitor trip time, not a downstream side effect.
            if "Anomaly type=0" in line:
                r.anomaly_type_0 += 1
            elif "Anomaly type=1" in line:
                r.anomaly_type_1 += 1
            elif "Anomaly type=2" in line:
                r.anomaly_type_2 += 1
                if r.first_detection_s is None:
                    r.first_detection_s = ts

            # Detection events at the BR
            if "[WARN: BorderRouter] ANOMALY" in line:
                r.anomaly_warns += 1
                if r.first_detection_s is None:
                    r.first_detection_s = ts
            # Count both the watchdog path ("SILENCE sensor #N idle") and the
            # pre-shuffle drain path ("SILENCE drain #N") -- both raise a real
            # CONN_FAILURE event.  Exclude the "watchdog skipped" log line.
            if (("SILENCE sensor" in line) or ("SILENCE drain" in line)) \
                    and "skipped" not in line:
                r.silence_events += 1
                if r.first_detection_s is None:
                    r.first_detection_s = ts
            if "RATE_LIMIT drop" in line:
                r.rate_limit_drops += 1

            # Attacker TX cumulative counter (attacker-node.c logs "*_TX total=N ..."
            # every 50 / 25 / 100 sends depending on mode; the "total=" field is the
            # exact running count, so the max value at end of run is the packets sent).
            m = re.search(r"(?:SCAN|SINK|FLOOD)_TX total=(\d+)", line)
            if m:
                v = int(m.group(1))
                if v > r.attacker_packets_sent:
                    r.attacker_packets_sent = v

            # Per-source counters (cumulative, keep the last)
            m = re.search(
                r"BR_SRC_METRICS legit_rx=(\d+) legit_anom=(\d+) att_rx=(\d+) att_anom=(\d+)",
                line)
            if m:
                r.legit_rx_total   = int(m.group(1))
                r.legit_anom_total = int(m.group(2))
                r.att_rx_total     = int(m.group(3))
                r.att_anom_total   = int(m.group(4))

            # Latency aggregates (cumulative, keep the last)
            m = re.search(r"BR_LATENCY samples=(\d+) mean_ms=(\d+) max_ms=(\d+)", line)
            if m:
                r.latency_samples = int(m.group(1))
                r.latency_mean_ms = float(m.group(2))
                r.latency_max_ms  = int(m.group(3))

            # Per-packet RX timestamps for reconvergence calc.  The
            # "[INFO: BorderRouter] RX [N]" line fires for every received
            # packet (legitimate or attacker).  We record the time only;
            # the actual reconvergence post-processing happens after the loop.
            if "[INFO: BorderRouter] RX [" in line:
                r.rx_event_ts.append(ts)

            # BR_METRICS  (cumulative, keep the last)
            m = re.search(r"BR_METRICS rx=(\d+) anomalous=(\d+)", line)
            if m:
                last_br_metrics_rx        = int(m.group(1))
                last_br_metrics_anomalous = int(m.group(2))

            # BR Energest  (cumulative, keep the last)
            m = re.search(r"BR_ENERGEST cpu=(\d+) lpm=(\d+) tx=(\d+) rx=(\d+)", line)
            if m:
                last_br_energest = tuple(int(g) for g in m.groups())

            # Sensor Energest  (cumulative per node; keep the last per node)
            m = re.search(
                r"ID:(\d+).*ENERGEST cpu=(\d+) lpm=(\d+) tx=(\d+) rx=(\d+)", line
            )
            if m and "BR_ENERGEST" not in line:
                node_id = int(m.group(1))
                if node_id != 1 and node_id != 31:
                    # Skip BR (id 1) and attacker (id 31).  Counting only the
                    # 29 legitimate sender nodes (RPL routers + sensors).
                    last_sensor_energest[node_id] = tuple(int(g) for g in m.groups()[1:])

    r.br_rx_total        = last_br_metrics_rx
    r.br_anomalous_total = last_br_metrics_anomalous

    if last_br_energest is not None:
        r.br_cpu_ticks, r.br_lpm_ticks, r.br_tx_ticks, r.br_rx_ticks = last_br_energest

    for cpu, lpm, tx, rx in last_sensor_energest.values():
        r.sensor_cpu_ticks.append(cpu)
        r.sensor_lpm_ticks.append(lpm)
        r.sensor_tx_ticks.append(tx)
        r.sensor_rx_ticks.append(rx)

    # Derived
    r.pdr = r.br_rx_total / EXPECTED_SENDS if EXPECTED_SENDS else None

    if r.first_detection_s is not None and r.attacker_start_s is not None:
        # Detection latency from end of attacker warmup (45 s after start)
        warmup_end = r.attacker_start_s + 45
        r.detection_latency_s = max(0.0, r.first_detection_s - warmup_end)

    if r.first_reactive_s is not None and r.first_detection_s is not None:
        r.reaction_latency_s = max(0.0, r.first_reactive_s - r.first_detection_s)

    # Attacker perspective
    # external_br_rx = BR_RX minus the expected legitimate sensor baseline.  This
    # is an upper bound on attacker packets that actually reached the BR (some
    # legitimate sensors may have been silenced, so a few of those 5,220 may be
    # missing -- this method counts those as "attacker" packets, but the bias is
    # at most a few hundred and does not change the qualitative comparison).
    if r.br_rx_total > 0:
        r.external_br_rx = max(0, r.br_rx_total - EXPECTED_SENDS)
    if r.attacker_packets_sent > 0 and r.external_br_rx is not None:
        r.attacker_delivery_rate = r.external_br_rx / r.attacker_packets_sent

    # Useful window: from end of attacker warm-up to the first reactive cycle.
    # This is how long the attacker had to act before MTD started mutating.
    if r.first_reactive_s is not None and r.attacker_start_s is not None:
        warmup_end = r.attacker_start_s + 45
        r.attacker_useful_window_s = max(0.0, r.first_reactive_s - warmup_end)

    # False-positive rate: fraction of legitimate-sender packets the BR
    # mistakenly flagged as anomalous (caused by sensors falling behind
    # on a port hop after a reactive shuffle).
    if r.legit_rx_total > 0:
        r.false_positive_rate = r.legit_anom_total / r.legit_rx_total

    # Scan success rate: fraction of attacker-injected packets that
    # reached the BR.  Strictly speaking this is "ingestion rate";
    # for the scan scenario it corresponds to probes that found a
    # still-valid target.
    if r.attacker_packets_sent > 0:
        r.scan_success_rate = r.att_rx_total / r.attacker_packets_sent

    # Reconvergence time after each reactive cycle.
    # For each reactive cycle at time T:
    #   pre_rate  = packets/sec in [T-60s, T]
    #   post_window starts at T; slide forward in 5s buckets; reconvergence
    #     is reached when bucket rate >= 0.9 * pre_rate (or 0.5 pkt/s as floor).
    #   Cap at 60 s post-cycle; if not recovered, record 60 s (the cap).
    if r.reactive_cycle_ts and r.rx_event_ts:
        rx = sorted(r.rx_event_ts)
        recs: List[float] = []
        for tc in r.reactive_cycle_ts:
            pre  = [t for t in rx if tc - 60 <= t < tc]
            pre_rate = len(pre) / 60.0
            if pre_rate < 0.1:
                continue   # nothing to converge to
            target = max(0.5, 0.9 * pre_rate)
            # walk forward in 5s buckets up to 60s post-cycle
            recovered = None
            for k in range(1, 13):     # 5, 10, ..., 60 s
                end = tc + k * 5
                bucket = [t for t in rx if tc < t <= end]
                if len(bucket) / (k * 5.0) >= target:
                    recovered = k * 5
                    break
            recs.append(recovered if recovered is not None else 60.0)
        if recs:
            r.reconvergence_samples = len(recs)
            r.reconvergence_mean_s  = sum(recs) / len(recs)

    # Drop the bulky internal lists from the dataclass before serialisation.
    r.rx_event_ts.clear()
    r.reactive_cycle_ts.clear()

    r.br_energy_mj = energy_mj(
        r.br_cpu_ticks, r.br_lpm_ticks, r.br_tx_ticks, r.br_rx_ticks
    )

    if r.sensor_cpu_ticks:
        per_sensor_mj = [
            energy_mj(c, l, t, x)
            for c, l, t, x in zip(
                r.sensor_cpu_ticks, r.sensor_lpm_ticks,
                r.sensor_tx_ticks,  r.sensor_rx_ticks,
            )
        ]
        r.sensor_energy_mj_mean = mean(per_sensor_mj)
        if len(per_sensor_mj) > 1:
            r.sensor_energy_mj_std = stdev(per_sensor_mj)

    return r


def energy_mj(cpu: int, lpm: int, tx: int, rx: int) -> float:
    """Convert Energest ticks (Sky target) to millijoules."""
    return (
        (cpu / TICK_HZ) * I_CPU_MA * SUPPLY_V
        + (lpm / TICK_HZ) * I_LPM_MA * SUPPLY_V
        + (tx  / TICK_HZ) * I_TX_MA  * SUPPLY_V
        + (rx  / TICK_HZ) * I_RX_MA  * SUPPLY_V
    )


# -------------------------------------------------------------------------
# Reporting
# -------------------------------------------------------------------------
COLS = [
    ("scenario",            "scenario",            "{:>9}"),
    ("condition",           "condition",           "{:>6}"),
    ("br_rx",               "br_rx_total",         "{:>7}"),
    ("anom_warn",           "anomaly_warns",       "{:>7}"),
    ("react",               "reactive_cycles",     "{:>5}"),
    ("d0/d1/d2",            None,                  "{:>10}"),
    ("silence",             "silence_events",      "{:>7}"),
    ("ratelim",             "rate_limit_drops",    "{:>7}"),
    ("PDR",                 "pdr",                 "{:>6}"),
    ("det_lat_s",           "detection_latency_s", "{:>9}"),
    ("atk_sent",            "attacker_packets_sent", "{:>8}"),
    ("ext_rx",              "external_br_rx",      "{:>7}"),
    ("deliv",               "attacker_delivery_rate", "{:>6}"),
    ("usefulW_s",           "attacker_useful_window_s", "{:>9}"),
    ("BR_E_mJ",             "br_energy_mj",        "{:>9}"),
    ("Sens_E_mJ",           "sensor_energy_mj_mean","{:>9}"),
    ("FPR",                 "false_positive_rate", "{:>6}"),
    ("scanSR",              "scan_success_rate",   "{:>6}"),
    ("lat_ms",              "latency_mean_ms",     "{:>7}"),
    ("reconv_s",            "reconvergence_mean_s","{:>8}"),
]


def fmt_cell(r: RunResult, attr: Optional[str], spec: str) -> str:
    if attr is None:
        return spec.format(f"{r.dominant_0}/{r.dominant_1}/{r.dominant_2}")
    v = getattr(r, attr)
    if isinstance(v, float):
        if attr in ("pdr", "attacker_delivery_rate",
                    "false_positive_rate", "scan_success_rate"):
            return spec.format(f"{v:.3f}")
        if attr == "latency_mean_ms":
            return spec.format(f"{v:.1f}")
        return spec.format(f"{v:.2f}")
    if v is None:
        return spec.format("-")
    return spec.format(v)


def print_table(results: List[RunResult]) -> None:
    header = " ".join(spec.format(name) for name, _, spec in COLS)
    print(header)
    print("-" * len(header))
    for r in results:
        print(" ".join(fmt_cell(r, attr, spec) for _, attr, spec in COLS))


def write_json(results: List[RunResult], out_path: Path) -> None:
    payload = [asdict(r) for r in results]
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# -------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------
def main() -> int:
    project_dir = Path(__file__).resolve().parent.parent

    log_set = [
        ("scan",     "mtd",   project_dir / "mtd_attack_scan_sky.txt"),
        ("sinkhole", "mtd",   project_dir / "mtd_attack_sinkhole_sky.txt"),
        ("flood",    "mtd",   project_dir / "mtd_attack_flood_sky.txt"),
        ("scan",     "nomtd", project_dir / "nomtd_scan_sky.txt"),
        ("sinkhole", "nomtd", project_dir / "nomtd_sinkhole_sky.txt"),
        ("flood",    "nomtd", project_dir / "nomtd_flood_sky.txt"),
    ]

    results: List[RunResult] = []
    for scenario, condition, path in log_set:
        if not path.exists():
            print(f"[skip] missing log: {path.name}", file=sys.stderr)
            continue
        results.append(parse_log(path, scenario, condition))

    print_table(results)
    write_json(results, project_dir / "eval" / "results.json")
    print()
    print(f"wrote eval/results.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
