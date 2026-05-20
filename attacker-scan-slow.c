/*
 * attacker-scan-slow.c
 *
 * Thin wrapper that compiles attacker-node.c with ATTACK_MODE=1 (scan)
 * and ATTACK_SEND_MS=500 (2 pkt/s).  Used by the attacker-speed sweep
 * (thesis Sec 7.3.6) as the low-rate (Nmap T1-equivalent stealth) data
 * point.
 *
 * Justification of the rate: 2 pkt/s matches a slow stealth scan
 * (Nmap T1 paranoid mode in the IPv4 world) and tests whether the MTD
 * orchestrator still detects and responds to long-running, low-volume
 * reconnaissance.
 */
#define ATTACK_MODE     1
#define ATTACK_SEND_MS  500   /* 2 pkt/s */
#include "attacker-node.c"
