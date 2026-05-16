/*
 * border-router.c
 *
 * Border Router + MTD Orchestrator process.
 *
 * This is the entry point for the Class 2 device that sits between
 * the sensor network and the external network (cloud / attacker).
 *
 * It does three things:
 *   1. Starts as an RPL DAG root, forming the 6LoWPAN DODAG that all
 *      sensor nodes join.
 *   2. Starts the MTD orchestrator, which runs the periodic shuffle
 *      and port-hop timers and reacts to anomaly reports.
 *   3. Listens for incoming sensor data on SENSOR_UDP_SERVER_PORT and
 *      counts packet delivery (used as the PDR metric in evaluation).
 *
 * Anomaly detection -- application-layer payload port check:
 *   Every sensor payload carries a "port=<active_port>" field that
 *   reflects the sensor's current MTD port identity.  After each port
 *   hop the orchestrator updates its expected port (mtd_get_current_port()).
 *   If an incoming packet's payload port does not match the expected value
 *   it is counted as a stale-port / replay anomaly and reported to the
 *   orchestrator, which may trigger a reactive MTD cycle.
 *
 *   NOTE: We deliberately do NOT use receiver_port for this check.
 *   simple-udp registers on a fixed local port (5678), so receiver_port
 *   in the callback is ALWAYS 5678 regardless of which MTD port is
 *   currently active.  The payload port field is the correct token.
 *
 * Thesis reference: System Design – Sections 5.3, 5.5
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/routing/rpl-lite/rpl-dag-root.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"
#include "sys/energest.h"

#include "mtd-lib/mtd-orchestrator.h"
#include "project-conf.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/*
 * Unity-build: pull the MTD implementation files into this translation unit.
 * Each file defines its own LOG_MODULE; #undef between includes prevents
 * -Werror from treating the redefinitions as errors.
 */
#undef LOG_MODULE
#undef LOG_LEVEL
#include "mtd-lib/ipv6-shuffle.c"
#undef LOG_MODULE
#undef LOG_LEVEL
#include "mtd-lib/port-hopper.c"
#undef LOG_MODULE
#undef LOG_LEVEL
#include "mtd-lib/mtd-orchestrator.c"
#undef LOG_MODULE
#undef LOG_LEVEL

#define LOG_MODULE  "BorderRouter"
#define LOG_LEVEL   LOG_LEVEL_INFO

/*---------------------------------------------------------------------------*/
/* Metrics counters (printed to log for evaluation)                          */
/*---------------------------------------------------------------------------*/
static uint32_t pkts_received  = 0;
static uint32_t pkts_anomalous = 0;

/*---------------------------------------------------------------------------*/
/* UDP connection for receiving sensor data                                  */
/*---------------------------------------------------------------------------*/
static struct simple_udp_connection server_conn;

/*---------------------------------------------------------------------------*/
/*
 * parse_payload_port -- extract the port=N field from a sensor payload.
 *
 * Sensor and attacker payloads have the format:
 *   "seq=<n>,port=<p>"      (legitimate sensor)
 *   "ATTACK seq=<n>,port=<p>"  (attacker node)
 *
 * Returns the parsed port value, or 0 if the field is absent or malformed.
 * A null terminator is written into a local copy so strstr/atoi are safe.
 */
static uint16_t
parse_payload_port(const uint8_t *data, uint16_t datalen)
{
  char buf[64];
  uint16_t copylen = (datalen < (sizeof(buf) - 1)) ? datalen : (sizeof(buf) - 1);

  memcpy(buf, data, copylen);
  buf[copylen] = '\0';

  char *p = strstr(buf, "port=");
  if(p == NULL) {
    return 0;
  }
  return (uint16_t)atoi(p + 5);
}

/*---------------------------------------------------------------------------*/
/*
 * Receive callback -- handles data from sensor nodes (and potentially attackers).
 *
 * Anomaly detection logic:
 *   1. Parse the "port=N" field from the payload.
 *   2. Compare it to mtd_get_current_port() (the orchestrator's expected port).
 *   3. Mismatch and port is not the initial SENSOR_UDP_CLIENT_PORT
 *      (first packet after init before any hop) → anomaly.
 *
 * This correctly identifies:
 *   - Attacker nodes that always embed a fixed stale port.
 *   - Sensor nodes that missed a CMD_PORT_HOP and are still using an old port.
 */
static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  /*
   * Rate limiting -- enforced only when a flooding episode is active
   * (cpu_load_pct > MTD_CPU_THRESHOLD_PCT as measured by the orchestrator's
   * Energest monitor).  When the per-second packet cap MTD_RATE_LIMIT_PPS
   * is exceeded, the packet is silently discarded to protect the CPU.
   */
#ifndef MTD_DISABLED
  if(mtd_rate_limit_check()) {
    return;   /* packet dropped by rate limiter */
  }
  /* Feed the packet-rate flood monitor (CPU_LOAD proxy, thesis Sec 5.3.3).
   * Counted BEFORE the anomaly check so flood traffic is registered even
   * when individual packets are flagged as STALE_PORT. */
  mtd_packet_rate_tick();
#endif

  pkts_received++;

  /*
   * Register this sender so the orchestrator can later push CMD_PORT_HOP
   * and CMD_ADDR_SHUFFLE back to it.  Duplicate registrations are a no-op.
   */
#ifndef MTD_DISABLED
  mtd_register_sensor(sender_addr);
#endif

  /* Extract the application-level port identity token from the payload */
  uint16_t payload_port = parse_payload_port(data, datalen);

  /*
   * Anomaly check: payload port must match the currently expected port.
   * We allow SENSOR_UDP_CLIENT_PORT (initial value, before any hop) as
   * a grace token so the very first packet after boot is never falsely flagged.
   */
  /*
   * Anomaly check -- realistic sliding-window detection:
   *
   *   Accept: current_port (fully up-to-date sensor)
   *           previous_port (missed exactly one hop -- sliding window tolerance)
   *           SENSOR_UDP_CLIENT_PORT (8765) ONLY while initial grace is active
   *             (first two hop cycles, ~120 s) -- thereafter 8765 is anomalous.
   *
   * The initial grace covers the boot-up period before sensors have received
   * their first port update.  After the second hop every actively transmitting
   * sensor has received ≥12 piggyback replies and is expected to be current.
   * An attacker replaying 8765 (or any port ≥2 hops old) is then detected.
   */
  uint8_t port_ok =
    (payload_port == 0) ||
    (payload_port == mtd_get_current_port()) ||
    (payload_port == mtd_get_previous_port()) ||
    (mtd_initial_grace_active() && payload_port == SENSOR_UDP_CLIENT_PORT);

  if(payload_port != 0 && !port_ok) {
    pkts_anomalous++;
    LOG_WARN("ANOMALY pkt #%lu payload_port=%u expected=%u from ",
             (unsigned long)pkts_received,
             payload_port, mtd_get_current_port());
    LOG_WARN_6ADDR(sender_addr);
    LOG_WARN_("\n");
    /*
     * Suppress STALE_PORT classification while a flood is being mitigated.
     * Aggressive reactive shuffling under flood causes legitimate sensors
     * to occasionally fall two hops behind on their port token, which
     * would otherwise saturate the STALE_PORT counter and outweigh the
     * CPU_LOAD signal in the dominant-type selector.  The packet is still
     * dropped (the return below); we just do not feed the typed counter.
     */
#ifndef MTD_DISABLED
    if(!mtd_flood_active()) {
      mtd_report_anomaly();
    }
#else
    mtd_report_anomaly();
#endif
    return;
  }

  /*
   * Piggyback port update -- send CMD_PORT_HOP back to this sensor immediately
   * while the reverse IP route is still fresh in the stack.  This is the
   * primary mechanism ensuring all active sensors stay current with the MTD
   * port, working around RPL-Lite non-storing mode's lack of proactive
   * downward routes.
   */
#ifndef MTD_DISABLED
  mtd_send_port_update(sender_addr);
#endif

  /* Valid packet -- log it for PDR calculation */
  LOG_INFO("RX [%lu] payload_port=%u from ", (unsigned long)pkts_received, payload_port);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_(" len=%u data=%.*s\n",
            datalen, (int)datalen, (char *)data);

  /* Periodic metrics snapshot every 50 packets */
  if(pkts_received % 50 == 0) {
    LOG_INFO("METRICS rx=%lu anomalous=%lu\n",
             (unsigned long)pkts_received,
             (unsigned long)pkts_anomalous);
  }
}

/*---------------------------------------------------------------------------*/
PROCESS(border_router_process, "Border Router + MTD Orchestrator");
AUTOSTART_PROCESSES(&border_router_process);
/*---------------------------------------------------------------------------*/

PROCESS_THREAD(border_router_process, ev, data)
{
  static struct etimer metrics_timer;

  PROCESS_BEGIN();

  LOG_INFO("Border router starting\n");

  /*
   * Step 1 -- Become the RPL DAG root.
   * This node will send RPL DIO messages, and sensor nodes will
   * join the DODAG and establish routes back to this node.
   */
  NETSTACK_ROUTING.root_start();
  LOG_INFO("RPL DAG root started\n");

  /*
   * Step 2 -- Register the server UDP connection.
   * Sensor nodes send data to SENSOR_UDP_SERVER_PORT (5678).
   */
  simple_udp_register(&server_conn,
                      SENSOR_UDP_SERVER_PORT,
                      NULL,
                      0,
                      udp_rx_callback);
  LOG_INFO("Listening on UDP port %u\n", SENSOR_UDP_SERVER_PORT);

  /*
   * Step 3 -- Start the MTD orchestrator.
   * This arms the proactive shuffle/hop timers and the port-hop timer.
   *
   * When compiled with -DMTD_DISABLED=1 (used by mtd_nomtd.csc) the
   * orchestrator is NOT started, giving an undefended control condition
   * for evaluating raw attack impact without any MTD response.
   */
#ifndef MTD_DISABLED
  mtd_orchestrator_init();
#else
  LOG_INFO("MTD orchestrator DISABLED (MTD_DISABLED=1) -- no shuffle/hop timers\n");
#endif /* MTD_DISABLED */

  /* Print a metrics summary every 5 minutes */
  etimer_set(&metrics_timer, 5 * 60 * CLOCK_SECOND);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&metrics_timer));

    /* Flush and print Energest counters for the border router itself */
    energest_flush();
    LOG_INFO("BR_ENERGEST cpu=%llu lpm=%llu tx=%llu rx=%llu\n",
             (unsigned long long)energest_type_time(ENERGEST_TYPE_CPU),
             (unsigned long long)energest_type_time(ENERGEST_TYPE_LPM),
             (unsigned long long)energest_type_time(ENERGEST_TYPE_TRANSMIT),
             (unsigned long long)energest_type_time(ENERGEST_TYPE_LISTEN));

    LOG_INFO("BR_METRICS rx=%lu anomalous=%lu\n",
             (unsigned long)pkts_received,
             (unsigned long)pkts_anomalous);

    etimer_reset(&metrics_timer);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
