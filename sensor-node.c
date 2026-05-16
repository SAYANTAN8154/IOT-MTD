/*
 * sensor-node.c
 *
 * Class 1 Tmote Sky sensor node for the MTD-IoT system.
 *
 * Behaviour:
 *  - Joins the RPL DODAG formed by the border router (orchestrator)
 *  - Sends a periodic UDP data packet to the border router every
 *    SENSOR_SEND_INTERVAL seconds; the payload includes the current
 *    active_port so the BR can do application-layer anomaly detection
 *  - Listens for three types of commands from the orchestrator:
 *      CMD_PORT_HOP    (0x01): switch active_port to the new value
 *      CMD_ADDR_ACK    (0x02): orchestrator acknowledges a shuffle
 *      CMD_ADDR_SHUFFLE(0x03): randomise this node's own IPv6 IID
 *  - Logs Energest counters every ENERGEST_LOG_INTERVAL seconds
 *    so that energy overhead can be parsed from the Cooja log
 *
 * Thesis reference: System Design – Sections 5.3, 5.6, 5.7
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip-ds6.h"
#include "sys/energest.h"
#include "sys/log.h"
#include "lib/random.h"
#include "project-conf.h"
#include "mtd-lib/ipv6-shuffle.h"

/* Unity-build: ipv6_shuffle_address() is defined here, not as a
 * separately-compiled object, because MODULES_REL is not reliable
 * in this Contiki-NG/Cooja build environment. */
#undef LOG_MODULE
#undef LOG_LEVEL
#include "mtd-lib/ipv6-shuffle.c"
#undef LOG_MODULE
#undef LOG_LEVEL

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define LOG_MODULE  "SensorNode"
#define LOG_LEVEL   LOG_LEVEL_INFO

/*---------------------------------------------------------------------------*/
/* Command bytes sent by the orchestrator                                     */
/*---------------------------------------------------------------------------*/
#define CMD_PORT_HOP     0x01   /* payload: 2-byte new port (big-endian) */
#define CMD_ADDR_ACK     0x02   /* payload: none -- orchestrator ack       */
#define CMD_ADDR_SHUFFLE 0x03   /* payload: none -- shuffle own IPv6 IID   */

/*---------------------------------------------------------------------------*/
/* Energest logging interval (every 60 s)                                    */
/*---------------------------------------------------------------------------*/
#define ENERGEST_LOG_INTERVAL  (60 * CLOCK_SECOND)

/*---------------------------------------------------------------------------*/
/* State                                                                      */
/*---------------------------------------------------------------------------*/
static struct simple_udp_connection udp_conn;
static uint16_t active_port = SENSOR_UDP_CLIENT_PORT;
static uint32_t seq_num     = 0;

/*---------------------------------------------------------------------------*/
/* Forward declarations                                                       */
/*---------------------------------------------------------------------------*/
static void reregister_udp(uint16_t new_port);
static void log_energest(void);

/*---------------------------------------------------------------------------*/
PROCESS(sensor_node_process, "MTD Sensor Node");
AUTOSTART_PROCESSES(&sensor_node_process);
/*---------------------------------------------------------------------------*/

/*
 * UDP receive callback.
 * Handles commands pushed down from the MTD orchestrator on the border router.
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
  if(datalen < 1) {
    return;
  }

  uint8_t cmd = data[0];

  if(cmd == CMD_PORT_HOP && datalen >= 3) {
    /* Extract 2-byte new port (big-endian) */
    uint16_t new_port = ((uint16_t)data[1] << 8) | data[2];
    LOG_INFO("CMD_PORT_HOP: switching port %u -> %u\n", active_port, new_port);
    reregister_udp(new_port);

  } else if(cmd == CMD_ADDR_ACK) {
    LOG_INFO("CMD_ADDR_ACK: orchestrator acknowledged address shuffle\n");

  } else if(cmd == CMD_ADDR_SHUFFLE) {
    /*
     * Orchestrator is requesting an IPv6 IID shuffle on this node.
     * ipv6_shuffle_address() randomises u16[4..7] of the link-local
     * address while keeping the /64 prefix intact, then removes the
     * old address and installs the new one via uip_ds6_addr_add().
     */
    LOG_INFO("CMD_ADDR_SHUFFLE: randomising local IPv6 IID\n");
    ipv6_shuffle_address();

  } else {
    LOG_WARN("Unknown command 0x%02x (len=%u)\n", cmd, datalen);
  }
}

/*---------------------------------------------------------------------------*/
/*
 * Switch to a new active port.
 *
 * simple-udp has no unregister/re-register API, so we cannot change the
 * socket-level source port.  Instead we update active_port, which is
 * embedded in every outgoing payload as "port=<active_port>".  The border
 * router uses this field for its application-layer anomaly check, so the
 * MTD port-identity mechanism works correctly without requiring OS-level
 * socket changes.
 *
 * Incoming orchestrator commands are still received on the original
 * SENSOR_UDP_CLIENT_PORT (the registered local port).
 */
static void
reregister_udp(uint16_t new_port)
{
  active_port = new_port;
  LOG_INFO("Active port updated to %u\n", active_port);
}

/*---------------------------------------------------------------------------*/
/*
 * Print Energest counters to the Cooja log.
 * Format:  ENERGEST cpu=<ticks> lpm=<ticks> tx=<ticks> rx=<ticks>
 * This line is parsed by the evaluation script.
 */
static void
log_energest(void)
{
  energest_flush();
  LOG_INFO("ENERGEST cpu=%llu lpm=%llu tx=%llu rx=%llu\n",
           (unsigned long long)energest_type_time(ENERGEST_TYPE_CPU),
           (unsigned long long)energest_type_time(ENERGEST_TYPE_LPM),
           (unsigned long long)energest_type_time(ENERGEST_TYPE_TRANSMIT),
           (unsigned long long)energest_type_time(ENERGEST_TYPE_LISTEN));
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(sensor_node_process, ev, data)
{
  static struct etimer send_timer;
  static struct etimer energest_timer;
  uip_ipaddr_t dest_addr;

  PROCESS_BEGIN();

  /* Initialise the PRNG (Contiki-NG seeds it internally from the node ID) */
  random_init();

  /* Register UDP on the default client port */
  simple_udp_register(&udp_conn,
                      SENSOR_UDP_CLIENT_PORT,
                      NULL,
                      SENSOR_UDP_SERVER_PORT,
                      udp_rx_callback);

  /* Stagger initial send to avoid synchronised traffic bursts */
  etimer_set(&send_timer,
             SENSOR_SEND_INTERVAL +
             (random_rand() % (SENSOR_SEND_INTERVAL / 2)));

  etimer_set(&energest_timer, ENERGEST_LOG_INTERVAL);

  LOG_INFO("Sensor node started. Sending every %d s, initial port=%u\n",
           SENSOR_SEND_INTERVAL_S, active_port);

  while(1) {
    PROCESS_WAIT_EVENT();

    /*--------------------------------------------------------------------*/
    /* Periodic data transmission                                          */
    /*--------------------------------------------------------------------*/
    if(etimer_expired(&send_timer)) {

      if(NETSTACK_ROUTING.node_is_reachable() &&
         NETSTACK_ROUTING.get_root_ipaddr(&dest_addr)) {

        /*
         * Payload format: "seq=<n>,port=<p>,t=<ms>"
         *   port  -- application-layer MTD identity token (BR checks it)
         *   t     -- TX timestamp in clock_time() ticks at send moment;
         *            the BR diffs it against its own clock_time() on
         *            receive to compute per-packet end-to-end latency.
         */
        char buf[48];
        unsigned long t_tx = (unsigned long)clock_time();
        int len = snprintf(buf, sizeof(buf), "seq=%lu,port=%u,t=%lu",
                           (unsigned long)seq_num++, active_port, t_tx);

        simple_udp_sendto(&udp_conn, buf, len, &dest_addr);
        LOG_INFO("TX seq=%lu port=%u to ", (unsigned long)(seq_num - 1), active_port);
        LOG_INFO_6ADDR(&dest_addr);
        LOG_INFO_("\n");

      } else {
        LOG_INFO("Not yet routable -- skipping TX (seq=%lu)\n",
                 (unsigned long)seq_num);
      }

      etimer_reset(&send_timer);
    }

    /*--------------------------------------------------------------------*/
    /* Periodic Energest logging                                           */
    /*--------------------------------------------------------------------*/
    if(etimer_expired(&energest_timer)) {
      log_energest();
      etimer_reset(&energest_timer);
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
