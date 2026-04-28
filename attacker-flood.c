/*
 * attacker-flood.c
 *
 * Thin wrapper that compiles attacker-node.c with ATTACK_MODE=3 (flood).
 * Used by mtd_attack_flood.csc / mtd_nomtd_flood.csc to produce an
 * independent attacker firmware binary per scenario, avoiding the Make
 * build-cache pitfall where -DDEFINES changes do not invalidate
 * attacker-node.o.
 *
 * Thesis reference: Attack Design - Section 5.3.3 (CoAP/UDP Flood).
 */
#define ATTACK_MODE 3
#include "attacker-node.c"
