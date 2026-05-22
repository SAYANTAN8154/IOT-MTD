# MTD-IoT Session Handoff

_Last updated: 2026-05-20_

This file captures the volatile per-session state needed to pick up the thesis work in a fresh Claude Code session. For durable facts (design rationale, file paths, threshold values) see the auto-loaded memory entries in `C:\Users\sayan\.claude\projects\C--Users-sayan-Semester-4\memory\`.

---

## 1. Where the work stands

The Evaluation chapter (§8) is largely complete with single-trial numbers across three scenarios × two conditions. Recent work focused on:

- **Source-aware per-source counters at BR** (landed). `border-router.c:74-77` now tracks `legit_rx`, `legit_anomalous`, `attacker_rx`, `attacker_anomalous` and emits them in the `BR_METRICS` log line. This unblocked false-positive rate and per-source detection rate in the eval.
- **Source-aware rate limiting** (landed). `MTD_RATE_LIMIT_MULTIPLIER` in `project-conf.h`; only the known attacker IID is throttled, legit sensors exempt. Cap is computed adaptively from sensor count × send interval.
- **Adaptive flood thresholds + proactive timer jitter** (landed). See `MTD_FLOOD_PPS_THRESHOLD`, `MTD_JITTER_PCT` in `project-conf.h`.
- **Five security metrics in parse_logs.py** (landed): `p_recon`, `p_rediscover_theoretical`, `p_rediscover_empirical`, `mttsf_proxy_s`, `c_atk_per_useful`, plus `p_detect` and `false_positive_rate`.
- **§7.3.6 Security metrics subsection added to `Body/8_Evaluation.tex`**, and §7.1.2 split into engineering vs security metric families.
- **Attacker-speed sweep wrappers built** (`attacker-scan-fast`, `attacker-scan-slow`). The justified rates are documented in the Evaluation chapter.

## 2. Current parser output (single trial each, MTD-on logs from new firmware)

```
scenario condition   br_rx anom_warn react   d0/d1/d2 silence ratelim    PDR det_lat_s atk_sent  ext_rx  deliv usefulW_s   BR_E_mJ Sens_E_mJ
    scan    mtd      4097    2340    24     17/7/0      10       0  0.785    375.21    18500       0  0.000    375.24 108567.11 107100.54
sinkhole    mtd      4167    1457    21     21/0/0       2       0  0.798    556.82    18925       0  0.000    557.99 107677.72 107076.61
   flood    mtd     18681    1365    30     1/26/3     175    5577  3.579      5.22    35200   13461  0.382      5.23 108956.97 107163.20
    scan  nomtd      4183       0     0      0/0/0       0       0  0.801         -    18600       0  0.000         - 108150.55 107023.97
sinkhole  nomtd      4187       0     0      0/0/0       0       0  0.802         -    18675       0  0.000         - 107278.25 107071.22
   flood  nomtd     30250       0     0      0/0/0       0       0  5.795         -    35600   25030  0.703         - 109693.90 107146.31
```

Qualitative claim that holds: all three reactive branches fire at least once, dominant branch matches the scenario, and flood delivery drops from 0.703 (no-MTD) to 0.382 (MTD).

## 3. Open tasks

From the live TaskList — keep this set in sync:

| # | Status | Task |
|---|--------|------|
| 6  | pending | Run 5-seed variance campaign (user, manual). DEFERRED per A1 in `LIMITATIONS_AND_TODO.txt` — seed spot check on flood (123456 vs 847291653) showed qualitative stability. |
| 7  | pending | Run attacker-speed sweep variants (user, manual). Wrappers exist; user runs Cooja. |
| 8  | pending | Extend parser to aggregate across multiple seeds → mean ± stdev. Only relevant once #6 is run. |
| 9  | pending | Rewrite headline claims in Evaluation chapter using inferential language (single-trial → "we observed" not "we measured"). |
| 11 | pending | Rerun 5 missing scenarios with new firmware (single trial). 1/6 logs use the new BR; the other 5 still need to be re-run by the user in Cooja. |

Completed recently:
- Security metrics (#1, #2, #3, #4, #5, #10, #12).

## 4. Recommended next concrete step

**Task #11 — rerun the remaining 5 scenarios with the new BR firmware** is the unblocker. Without it, the 5 stale logs are inconsistent with the new per-source counter format, and #9 (claim rewrite) can't be finalized because the headline numbers will shift.

After #11: do #9, then #8 only if #6 is in scope.

## 5. Build / run reminders

- **Build target:** Tmote Sky via `TARGET=sky`. Cooja `.csc` files in repo root.
- **MTD on:** default. **MTD off:** `-DMTD_DISABLED=1` (drives the `mtd_nomtd.csc` variant).
- **Attack mode:** `-DATTACK_MODE={1,2,3}` for scan / sinkhole / flood. Default 1 (scan).
- **Flash budget:** very tight — see [[project-flash-budget]] memory entry. Adding fields to logs or new counters needs a flash check.
- **Eval pipeline:** `python eval/parse_logs.py` → `eval/results.json` + console table. `python eval/make_figures.py` → PNGs to `eval/figures/` and `Master_Thesis___MTD/Images/Evaluation/`.
- **Shell:** PowerShell on Windows; Bash also available via the Bash tool.

## 6. Watch-outs

- `parse_logs.py` regex matches `BR_METRICS rx=... anomalous=...` but the new BR emits `rx=... anom=... lr=... la=... ar=... aa=...`. Verify the parser actually reads the new per-source fields; some regex paths may still hit the old format and silently miss data.
- The flood MTD column shows `PDR=3.579` (>1) because `pdr` is computed as `br_rx / expected_legit_sends` and flood rx includes attacker traffic. Expected behaviour given the metric definition, but worth flagging in the chapter.
- Reactive cycles in scan = 24 but `d0/d1/d2 = 17/7/0` — the 7 CONN_FAILURE cycles under scan are legit (probing causes routing churn) but should be sanity-checked against the priority order CONN_FAILURE > CPU_LOAD > STALE_PORT.

---

_When this file's content goes stale, update or delete it — don't let it lie._
