/*
 * border-router-nomtd.c
 *
 * Thin wrapper that compiles border-router.c with MTD_DISABLED=1.
 * Used by mtd_nomtd.csc to produce an undefended control condition:
 * no IPv6 shuffles, no port hops, no anomaly detection.
 * All sensor traffic is accepted unconditionally regardless of port.
 *
 * Thesis reference: Evaluation – Section 7 (Control Condition / No-MTD Baseline)
 */
#define MTD_DISABLED 1
#include "border-router.c"
