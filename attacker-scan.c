/*
 * attacker-scan.c
 *
 * Thin wrapper that compiles attacker-node.c with ATTACK_MODE=1 (scan).
 * Used by mtd_attack_scan.csc / mtd_nomtd_scan.csc to produce an independent
 * attacker firmware binary per scenario, avoiding the Make build-cache
 * pitfall where -DDEFINES changes do not invalidate attacker-node.o.
 *
 * Thesis reference: Attack Design - Section 5.3.1 (IPv6 Scan).
 */
#define ATTACK_MODE 1
#include "attacker-node.c"
