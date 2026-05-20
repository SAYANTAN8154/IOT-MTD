/*
 * attacker-scan-fast.c
 *
 * Thin wrapper that compiles attacker-node.c with ATTACK_MODE=1 (scan)
 * and ATTACK_SEND_MS=20 (50 pkt/s).  Used by the attacker-speed sweep
 * (thesis Sec 7.3.6) as the high-rate data point.
 *
 * Justification of the rate: 50 pkt/s is close to the practical maximum
 * a single IEEE 802.15.4 attacker mote can sustain after CSMA/CA
 * backoff and multi-hop overhead.  Higher rates (e.g.\ 100+ pkt/s)
 * exceed the channel capacity and the on-the-air rate stays at this
 * ceiling regardless of the configured value.
 */
#define ATTACK_MODE     1
#define ATTACK_SEND_MS  20    /* 50 pkt/s */
#include "attacker-node.c"
