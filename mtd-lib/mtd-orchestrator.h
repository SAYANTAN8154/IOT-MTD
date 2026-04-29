#ifndef MTD_ORCHESTRATOR_H_
#define MTD_ORCHESTRATOR_H_

#include "contiki.h"

/*---------------------------------------------------------------------------*/
/* Anomaly type classification                                                */
/*---------------------------------------------------------------------------*/
/*
 * The orchestrator tracks anomaly counts per type so the reactive handler
 * can select the most appropriate MTD technique:
 *
 *   STALE_PORT   -- payload port does not match current/previous MTD port.
 *                  Signals active scanning or replay; counter driven by the
 *                  application-layer port check in border-router.c.
 *                  Reactive response: IPv6 IID shuffle (change address
 *                  identity to break ongoing reconnaissance).
 *
 *   CONN_FAILURE -- unicast CMD_PORT_HOP or CMD_ADDR_SHUFFLE delivery failed.
 *                  Signals probing-induced routing disruption; counter driven
 *                  by send-failure detection in broadcast helpers.
 *                  Reactive response: immediate port hop (restore a clean
 *                  communication channel with a new port identity).
 *
 *   CPU_LOAD     -- Energest CPU ratio exceeds MTD_CPU_THRESHOLD_PCT within
 *                  a MTD_CPU_WINDOW_S monitoring window.  Signals flooding.
 *                  Reactive response: IPv6 IID shuffle + activate rate
 *                  limiting to throttle excess traffic at the application
 *                  layer.
 */
typedef enum {
  MTD_ANOMALY_STALE_PORT   = 0,   /* wrong MTD port → scanning / replay    */
  MTD_ANOMALY_CONN_FAILURE = 1,   /* delivery failure → probing disruption  */
  MTD_ANOMALY_CPU_LOAD     = 2,   /* CPU overload → flooding attack         */
  MTD_ANOMALY_TYPE_COUNT   = 3
} mtd_anomaly_type_t;

/*---------------------------------------------------------------------------*/
/* MTD Orchestrator API                                                       */
/*---------------------------------------------------------------------------*/

/**
 * Initialise the MTD orchestrator.
 * Starts the periodic shuffle and port-hop timers.
 * Call this once from border-router.c after the RPL root is started.
 */
void mtd_orchestrator_init(void);

/**
 * Report a typed anomaly event to the orchestrator.
 * The per-type counter is incremented.  When the total anomaly count across
 * all types reaches MTD_THREAT_THRESHOLD the reactive handler fires and
 * selects a technique based on the dominant anomaly type.
 */
void mtd_report_anomaly_typed(mtd_anomaly_type_t type);

/**
 * Convenience wrapper -- reports MTD_ANOMALY_STALE_PORT.
 * Kept for backward compatibility with existing call sites in border-router.c.
 */
void mtd_report_anomaly(void);

/**
 * Application-layer rate limiter.
 *
 * Called at the top of the UDP receive callback for every incoming packet.
 * Maintains a rolling count over a 1-second window; returns 1 (drop) once
 * the count exceeds MTD_RATE_LIMIT_PPS.  Rate limiting is enforced only
 * while a flooding threat (MTD_ANOMALY_CPU_LOAD) is active.
 *
 * Returns: 0 = accept packet, 1 = drop packet (rate limit exceeded).
 */
uint8_t mtd_rate_limit_check(void);

/**
 * Get the current active UDP port for sensor communication.
 * Sensor nodes query this after receiving a port-update command.
 */
uint16_t mtd_get_current_port(void);

/**
 * Get the previous active UDP port (one hop ago).
 * The anomaly check accepts this value as well as current_port to
 * tolerate sensors that missed exactly one CMD_PORT_HOP delivery.
 * An attacker replaying a port two or more hops old is still detected.
 */
uint16_t mtd_get_previous_port(void);

/**
 * Returns non-zero while the initial boot-port (SENSOR_UDP_CLIENT_PORT)
 * grace is still active -- i.e. before the second port hop has fired.
 * After the second hop all sensors have had >=120 s of piggyback replies
 * and are expected to be running a current MTD port; port 8765 then
 * becomes anomalous just like any other stale value.
 */
uint8_t mtd_initial_grace_active(void);

/**
 * Send a CMD_PORT_HOP reply with current_port directly to one sensor.
 * Called from border-router.c immediately after a valid upward packet
 * arrives, while the reverse IP route is still fresh in the stack.
 * This piggyback mechanism ensures every actively transmitting sensor
 * learns the current port without relying on downward RPL routing.
 */
void mtd_send_port_update(const uip_ipaddr_t *addr);

/**
 * Register a sensor node address so the orchestrator can unicast
 * CMD_PORT_HOP and CMD_ADDR_SHUFFLE to it.
 * Call this from border-router.c each time a valid packet arrives.
 * Uses a ring buffer -- oldest entry evicted when full.
 *
 * Also updates the per-sensor last-seen timestamp used by the silence
 * watchdog (thesis Sec 5.3.2 -- RPL sinkhole detection).
 */
void mtd_register_sensor(const uip_ipaddr_t *addr);

/**
 * Feed the packet-rate monitor used as a Cooja-friendly proxy for the
 * Energest CPU% flood detector (thesis Sec 5.3.3).  Call once per
 * incoming application-layer packet at the border router.  When the
 * count within a MTD_CPU_WINDOW_S window exceeds MTD_FLOOD_PPS_THRESHOLD
 * the orchestrator reports MTD_ANOMALY_CPU_LOAD.
 */
void mtd_packet_rate_tick(void);

#endif /* MTD_ORCHESTRATOR_H_ */
