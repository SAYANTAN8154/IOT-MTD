# MTD-IoT

Adaptive Moving Target Defense (MTD) orchestrator for 6LoWPAN/RPL IoT
networks, implemented on Contiki-NG and evaluated under three attack
scenarios in the Cooja simulator with the Tmote Sky target.

The orchestrator runs on the border router and selects one of three
reactive MTD techniques based on the type of observed threat:

| Threat indicator | Reactive response                     |
| ---------------- | ------------------------------------- |
| `STALE_PORT`     | IPv6 IID shuffle                      |
| `CONN_FAILURE`   | UDP port hop                          |
| `CPU_LOAD`       | IPv6 shuffle + application rate limit |

Selection follows a fixed severity priority
(`CONN_FAILURE` > `CPU_LOAD` > `STALE_PORT`), so rare-but-severe events
always win the priority race against high-volume but low-severity
stale-port noise. A 60 s cooldown gate prevents oscillation and the
proactive shuffle / port-hop timers run independently in the background.

## Repository layout

```
border-router.c                    BR firmware with MTD orchestrator
border-router-nomtd.c              Same BR with MTD compiled out (control baseline)
sensor-node.c                      Sensor node firmware
attacker-node.c                    All three attack modes, selected by ATTACK_MODE
attacker-{scan,sinkhole,flood}.c   Per-mode wrappers (one .sky binary each)
project-conf.h                     All tunables (intervals, thresholds, ports)
mtd-lib/                           MTD library: orchestrator, port hopper, IPv6 shuffler
mtd_attack_*.csc                   Cooja MTD-on attack scenarios (3)
nomtd_*.csc                        Cooja no-MTD baseline scenarios (3)
eval/parse_logs.py                 Walks the Cooja logs, emits results.json
eval/make_figures.py               Generates the four evaluation figures (PNG)
```

## Attack scenarios

| Scenario | Mechanism                                                                      |
| -------- | ------------------------------------------------------------------------------ |
| Scan     | Binary CoAP probes (RFC 7252) with stale port in Uri-Query; RFC 7707 IID sweep |
| Sinkhole | Forged RPL DIO Control Message (RFC 6550 §6.3.1, 76 B) on `ff02::1`            |
| Flood    | Binary CoAP `CON GET` with randomised Message ID / Token                       |

The attacker mote sits at the network periphery, just outside the BR's
50 m transmission range but inside the 100 m interference range. Its
position is identical across all six scenarios.

## Build

Requires Contiki-NG v5.1 and the MSP430 toolchain (`msp430-gcc`,
`msp430-binutils`) for the Sky target.

```bash
make TARGET=sky                 # builds every binary in the directory
```

## Run a scenario

Open one of the `.csc` files in Cooja:

```bash
cooja mtd_attack_scan_sky.csc
```

Press *Start*; save the Log Listener output to a file (for example
`mtd_attack_scan_sky.txt`).

## Evaluate

```bash
python3 eval/parse_logs.py      # writes eval/results.json + prints a summary
python3 eval/make_figures.py    # writes the figures to eval/figures/
```

## Status

Single-trial evaluation across six 30-minute runs (3 MTD-on + 3 no-MTD
baseline). The single-trial scope and the radio-disruption approximation
of the sinkhole attack are documented as limitations in the thesis
Discussion chapter.

## License

BSD-3-Clause, matching Contiki-NG.
