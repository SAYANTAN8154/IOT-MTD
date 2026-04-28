/*
 * attacker-sinkhole.c
 *
 * Thin wrapper that compiles attacker-node.c with ATTACK_MODE=2 (sinkhole).
 * Used by mtd_attack_sinkhole.csc / mtd_nomtd_sinkhole.csc to produce an
 * independent attacker firmware binary per scenario, avoiding the Make
 * build-cache pitfall where -DDEFINES changes do not invalidate
 * attacker-node.o.
 *
 * Thesis reference: Attack Design - Section 5.3.2 (RPL Sinkhole).
 */
#define ATTACK_MODE 2
#include "attacker-node.c"
