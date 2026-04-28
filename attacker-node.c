/*
 * attacker-node.c
 *
 * Simulated adversary for the MTD-IoT evaluation (Cooja, TARGET=cooja).
 *
 * Three attack scenarios are implemented as a single compile-time
 * selector, ATTACK_MODE (set via DEFINES=ATTACK_MODE=<n> from the .csc
 * make-command).  Each scenario is engineered to trigger a specific
 * monitoring indicator in the MTD orchestrator, allowing the rule-based
 * technique-selection logic of thesis Sec 4.5.2 to be exercised.
 *
 *   ATTACK_MODE_SCAN     (1)  — thesis Sec 5.3.1
 *     IPv6 address scanning: the attacker sends 10 UDP probe packets
 *     per second to the border router with a deliberately stale
 *     port= field in the payload.  Each probe increments the BR's
 *     STALE_PORT counter.  Expected MTD response: IPv6 IID shuffle.
 *
 *   ATTACK_MODE_SINKHOLE (2)  — thesis Sec 5.3.2
 *     RPL sinkhole (approximation): the attacker floods the radio
 *     channel with high-rate link-local broadcasts, causing collisions
 *     that silence one or more legitimate sensors within its
 *     interference range.  The BR's silence watchdog detects the
 *     missing sensors and raises CONN_FAILURE.  Expected MTD response:
 *     port hop (restores a clean communication channel; the accompanying
 *     address shuffle separately forces RPL re-convergence).
 *
 *     NOTE: A fully faithful rank-1 DIO spoofing attack would require
 *     the external rpl-attacks framework (thesis Sec 5.2.1), which is
 *     not part of Contiki-NG v5.1 upstream.  The broadcast-flood
 *     approximation produces the same detection signal (sensor silence
 *     → CONN_FAILURE) and exercises the same reactive technique branch.
 *
 *   ATTACK_MODE_FLOOD    (3)  — thesis Sec 5.3.3
 *     CoAP flooding approximation: the attacker sends 20 UDP packets
 *     per second to the border router.  The BR's packet-rate monitor
 *     (a Cooja-friendly proxy for the Energest CPU% flood detector,
 *     since the contikimote target has no LPM signal) exceeds
 *     MTD_FLOOD_PPS_THRESHOLD and raises CPU_LOAD.  Expected MTD
 *     response: composite IPv6 shuffle + rate limiting.
 *
 * Thesis reference: Attack Design – Chapter 5 (Attack Scenarios).
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip.h"
#include "sys/etimer.h"
#include "sys/log.h"
#include "lib/random.h"
#include "project-conf.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define LOG_MODULE  "Attacker"
#define LOG_LEVEL   LOG_LEVEL_INFO

/*---------------------------------------------------------------------------*/
/* Per-mode cadence (milliseconds between sends)                             */
/*---------------------------------------------------------------------------*/
#if ATTACK_MODE == ATTACK_MODE_SCAN
  /* 10 probes/s (thesis Sec 5.3.1) */
  #define ATTACK_SEND_MS         100
  #define ATTACK_LABEL           "SCAN"
#elif ATTACK_MODE == ATTACK_MODE_SINKHOLE
  /* 5 broadcast storms/s — aggressive but within UDGM capacity */
  #define ATTACK_SEND_MS         200
  #define ATTACK_LABEL           "SINK"
#elif ATTACK_MODE == ATTACK_MODE_FLOOD
  /* 20 flood packets/s — comfortably above MTD_FLOOD_PPS_THRESHOLD
   * (30 pkts per MTD_CPU_WINDOW_S=10 s window → 3 pkt/s) */
  #define ATTACK_SEND_MS         50
  #define ATTACK_LABEL           "FLOOD"
#else
  #error "Unknown ATTACK_MODE — set ATTACK_MODE to 1, 2, or 3"
#endif

/* Stale-port constant used by SCAN and FLOOD probes.  After the BR's
 * initial port grace expires (two hops, ~120 s) this value is flagged
 * as a STALE_PORT anomaly on every packet. */
#define ATTACK_STALE_PORT        SENSOR_UDP_CLIENT_PORT   /* 8765 */

/* Start-up delay — lets the RPL DODAG converge and legitimate sensors
 * register before the attack begins.  Matches thesis evaluation protocol
 * (Sec 5.2.3 — "attacks begin after the first proactive shuffle cycle
 * at t = 30 s"). */
#define ATTACK_WARMUP_S          45
#define ATTACK_WARMUP            (ATTACK_WARMUP_S * CLOCK_SECOND)

/*---------------------------------------------------------------------------*/
/* State                                                                      */
/*---------------------------------------------------------------------------*/
static struct simple_udp_connection attack_conn;
static uint32_t                     seq_num = 0;

/*---------------------------------------------------------------------------*/
PROCESS(attacker_process, "MTD Attacker Node");
AUTOSTART_PROCESSES(&attacker_process);
/*---------------------------------------------------------------------------*/

/*
 * No-op UDP receive callback.  The attacker does not react to any
 * messages from the border router; all intelligence is encoded into
 * the outgoing attack traffic pattern.
 */
static void
attack_rx_callback(struct simple_udp_connection *c,
                   const uip_ipaddr_t *sender_addr, uint16_t sender_port,
                   const uip_ipaddr_t *receiver_addr, uint16_t receiver_port,
                   const uint8_t *data, uint16_t datalen)
{
  /* ignored */
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(attacker_process, ev, data)
{
  static struct etimer tx_timer;
  static struct etimer warmup_timer;
  static uint32_t pkts_sent = 0;
#if (ATTACK_MODE == ATTACK_MODE_SCAN) || (ATTACK_MODE == ATTACK_MODE_FLOOD)
  uip_ipaddr_t br_addr;
#endif
#if ATTACK_MODE == ATTACK_MODE_SINKHOLE
  uip_ipaddr_t bcast_addr;
#endif

  PROCESS_BEGIN();

  random_init();    /* Contiki-NG seeds PRNG from node ID internally */

  /*
   * Register on SENSOR_UDP_CLIENT_PORT so attack packets look source-port
   * identical to legitimate sensor traffic (the BR has no sender-port
   * filter).  Destination port SENSOR_UDP_SERVER_PORT (5678) for SCAN
   * and FLOOD; SINKHOLE uses link-local broadcast to the same port.
   */
  simple_udp_register(&attack_conn,
                      SENSOR_UDP_CLIENT_PORT,
                      NULL,
                      SENSOR_UDP_SERVER_PORT,
                      attack_rx_callback);

  LOG_INFO("Attacker started — mode=%s warmup=%ds cadence=%dms\n",
           ATTACK_LABEL, ATTACK_WARMUP_S, ATTACK_SEND_MS);

  /* Warm-up: let the DODAG converge first so the attack traffic hits
   * an established network, not an empty one. */
  etimer_set(&warmup_timer, ATTACK_WARMUP);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&warmup_timer));

  LOG_INFO("Warm-up complete — launching %s attack\n", ATTACK_LABEL);

#if ATTACK_MODE == ATTACK_MODE_SINKHOLE
  /* Link-local all-nodes (ff02::1) — target for the radio-disruption storm */
  uip_create_linklocal_allnodes_mcast(&bcast_addr);
#endif

  etimer_set(&tx_timer, (ATTACK_SEND_MS * CLOCK_SECOND) / 1000);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&tx_timer));

    /* Require a reachable root for unicast attacks.  Broadcast-mode
     * sinkhole still proceeds even if RPL has not yet converged, since
     * its effect is purely at the radio layer. */
#if (ATTACK_MODE == ATTACK_MODE_SCAN) || (ATTACK_MODE == ATTACK_MODE_FLOOD)
    int have_root = (NETSTACK_ROUTING.node_is_reachable() &&
                     NETSTACK_ROUTING.get_root_ipaddr(&br_addr));
#endif

#if ATTACK_MODE == ATTACK_MODE_SCAN
    /*
     * Thesis Sec 5.3.1 — IPv6 scan.  Send 10 UDP probes/s to the BR
     * with a deliberately stale port field.  Each probe appears to
     * the BR as a legitimate-looking sensor packet that, after the
     * initial grace window expires, fails the current/previous port
     * check → STALE_PORT anomaly (scan_rate indicator).
     *
     * In addition we vary the destination IID slightly every 100
     * packets, simulating the address-enumeration sweep described
     * in the thesis — Echo Request packets to every address in the
     * /64 prefix.
     */
    if(have_root) {
      uip_ipaddr_t probe_addr;
      uip_ipaddr_copy(&probe_addr, &br_addr);
      /* Occasionally perturb the low 16 bits to mimic a sweep; the
       * BR address itself is still hit frequently enough to keep
       * the anomaly rate near 10 pkt/s. */
      if((seq_num & 0x07) == 0) {
        probe_addr.u16[7] = random_rand();
      }
      char buf[48];
      int len = snprintf(buf, sizeof(buf),
                         "SCAN seq=%lu,port=%u",
                         (unsigned long)seq_num++,
                         (unsigned)ATTACK_STALE_PORT);
      simple_udp_sendto(&attack_conn, buf, len, &probe_addr);
      pkts_sent++;
      if((pkts_sent % 50) == 0) {
        LOG_INFO("SCAN_TX total=%lu last_seq=%lu target=",
                 (unsigned long)pkts_sent,
                 (unsigned long)(seq_num - 1));
        LOG_INFO_6ADDR(&probe_addr);
        LOG_INFO_("\n");
      }
    }

#elif ATTACK_MODE == ATTACK_MODE_SINKHOLE
    /*
     * Thesis Sec 5.3.2 — RPL sinkhole approximation.  Broadcast a
     * large UDP payload on the link-local all-nodes address at high
     * cadence.  Under Cooja's UDGM model, collisions within the
     * attacker's interference range cause legitimate sensor uplink
     * packets to be lost.  Sensors that fall silent for longer than
     * MTD_SILENCE_TIMEOUT_S are flagged by the BR's silence watchdog
     * as CONN_FAILURE (failure_rate indicator) — see
     * mtd-orchestrator.c :: silence_watchdog_cb().
     *
     * The payload carries a stale-port marker so that any packet the
     * attacker DOES manage to unicast-relay (e.g. in future rpl-attacks
     * integration) would also trip the STALE_PORT detector.
     */
    {
      char buf[64];
      int len = snprintf(buf, sizeof(buf),
                         "SINK seq=%lu,port=%u,rank=1",
                         (unsigned long)seq_num++,
                         (unsigned)ATTACK_STALE_PORT);
      /* Pad to a typical sensor packet size to match realistic
       * collision footprint. */
      while(len < 40 && len < (int)(sizeof(buf) - 1)) {
        buf[len++] = 'X';
      }
      buf[len] = '\0';
      simple_udp_sendto(&attack_conn, buf, len, &bcast_addr);
      pkts_sent++;
      if((pkts_sent % 25) == 0) {
        LOG_INFO("SINK_TX total=%lu last_seq=%lu (broadcast)\n",
                 (unsigned long)pkts_sent,
                 (unsigned long)(seq_num - 1));
      }
    }

#elif ATTACK_MODE == ATTACK_MODE_FLOOD
    /*
     * Thesis Sec 5.3.3 — CoAP flooding approximation.  Send 20 UDP
     * packets/s to the BR's server port.  The BR's packet-rate
     * monitor (CPU_LOAD proxy for Cooja contikimote) observes
     * count > MTD_FLOOD_PPS_THRESHOLD within one
     * MTD_CPU_WINDOW_S=10 s window and raises MTD_ANOMALY_CPU_LOAD.
     * The orchestrator's technique selector routes this to the
     * composite IPv6 shuffle + rate-limit branch.
     *
     * IMPORTANT: the payload MUST NOT contain the "port=" token that
     * legitimate sensor packets carry.  A CoAP GET flood (thesis
     * mechanism) has no port field, so at the BR parse_payload_port()
     * returns 0 and the STALE_PORT check is bypassed — leaving the
     * packet-rate monitor as the sole detection path, exactly as the
     * thesis describes.  If we embedded port=<stale> every flood
     * packet would trip STALE_PORT first and saturate the 5-anomaly
     * threshold before CPU_LOAD could accumulate, mis-routing the
     * response to the address-shuffle branch.
     */
    if(have_root) {
      char buf[72];
      int len = snprintf(buf, sizeof(buf),
                         "FLOOD seq=%lu coap GET /sensor/data",
                         (unsigned long)seq_num++);
      simple_udp_sendto(&attack_conn, buf, len, &br_addr);
      pkts_sent++;
      if((pkts_sent % 100) == 0) {
        LOG_INFO("FLOOD_TX total=%lu last_seq=%lu target=",
                 (unsigned long)pkts_sent,
                 (unsigned long)(seq_num - 1));
        LOG_INFO_6ADDR(&br_addr);
        LOG_INFO_("\n");
      }
    }
#endif

    etimer_set(&tx_timer, (ATTACK_SEND_MS * CLOCK_SECOND) / 1000);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
