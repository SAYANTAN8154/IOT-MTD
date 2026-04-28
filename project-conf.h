#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/*---------------------------------------------------------------------------*/
/* RPL Configuration                                                          */
/*---------------------------------------------------------------------------*/
/* Allow nodes to act as routers */
#define UIP_CONF_ROUTER 1

/* Maximum number of RPL instances */
#define RPL_CONF_MAX_INSTANCES  1

/* Maximum number of DAGs per instance */
#define RPL_CONF_MAX_DAG_PER_INSTANCE 1

/*---------------------------------------------------------------------------*/
/* MTD Configuration                                                          */
/*---------------------------------------------------------------------------*/
/* How often the orchestrator shuffles IPv6 addresses (seconds) */
#define MTD_SHUFFLE_INTERVAL_S   30
#define MTD_SHUFFLE_INTERVAL     (MTD_SHUFFLE_INTERVAL_S * CLOCK_SECOND)

/* How often port hopping occurs (seconds) */
#define MTD_PORT_HOP_INTERVAL_S  60
#define MTD_PORT_HOP_INTERVAL    (MTD_PORT_HOP_INTERVAL_S * CLOCK_SECOND)

/* Number of anomalies before triggering an immediate MTD response */
#define MTD_THREAT_THRESHOLD     5

/* Cooldown between successive reactive MTD cycles (thesis Sec 4.5.1,
 * Table 6). Prevents oscillation under a sustained attack and lets RPL
 * re-converge after a shuffle before a new one is initiated. */
#define MTD_COOLDOWN_S           60
#define MTD_COOLDOWN             (MTD_COOLDOWN_S * CLOCK_SECOND)

/* CPU load monitoring — Energest-based flooding detection            */
#define MTD_CPU_THRESHOLD_PCT    80   /* CPU% above which flooding is inferred (thesis Sec 5.3.3) */
#define MTD_CPU_WINDOW_S         10   /* monitoring window length (seconds)    */
#define MTD_CPU_WINDOW           (MTD_CPU_WINDOW_S * CLOCK_SECOND)

/* Packet-rate proxy for flood detection.  On the Cooja contikimote target
 * ENERGEST_TYPE_LPM never accumulates, so the CPU% ratio is unusable.  As
 * a second, target-independent indicator we count UDP packets per rate
 * window; when the count exceeds this threshold within a single window
 * we report MTD_ANOMALY_CPU_LOAD (flooding).  A real Tmote-Sky build can
 * still rely on the Energest CPU% path in parallel. */
#define MTD_FLOOD_PPS_THRESHOLD  30   /* >30 pkts within MTD_CPU_WINDOW_S → flood */

/* Rate limiting — application-layer packet cap per second            */
#define MTD_RATE_LIMIT_PPS       20   /* max packets/s before dropping excess  */

/* Sensor-silence watchdog — used to detect RPL sinkhole / routing disruption.
 * A registered sensor that has not transmitted for this many seconds is
 * flagged as a CONN_FAILURE anomaly.  Must be > 2*SENSOR_SEND_INTERVAL_S
 * so that a single missed transmission does not falsely trigger. */
#define MTD_SILENCE_TIMEOUT_S    45
#define MTD_SILENCE_TIMEOUT      (MTD_SILENCE_TIMEOUT_S * CLOCK_SECOND)
#define MTD_SILENCE_CHECK_S      15   /* watchdog poll interval */
#define MTD_SILENCE_CHECK        (MTD_SILENCE_CHECK_S * CLOCK_SECOND)

/* Port hopping range: random port in [BASE, BASE + RANGE) */
#define MTD_BASE_PORT            5000
#define MTD_PORT_RANGE           1000

/*---------------------------------------------------------------------------*/
/* Attack scenario selector (thesis Chapter 5)                               */
/*---------------------------------------------------------------------------*/
/* attacker-node.c reads ATTACK_MODE at compile time.  Set from the .csc
 * make-command via DEFINES=ATTACK_MODE=<n>.  Default: IPv6 scan. */
#define ATTACK_MODE_SCAN         1   /* thesis Sec 5.3.1 — ICMPv6 / UDP scan */
#define ATTACK_MODE_SINKHOLE     2   /* thesis Sec 5.3.2 — RPL rank-1 spoof  */
#define ATTACK_MODE_FLOOD        3   /* thesis Sec 5.3.3 — CoAP/UDP flood    */

#ifndef ATTACK_MODE
#define ATTACK_MODE              ATTACK_MODE_SCAN
#endif

/*---------------------------------------------------------------------------*/
/* UDP Communication                                                          */
/*---------------------------------------------------------------------------*/
#define SENSOR_UDP_SERVER_PORT   5678
#define SENSOR_UDP_CLIENT_PORT   8765

/* How often sensors send data (seconds) */
#define SENSOR_SEND_INTERVAL_S   10
#define SENSOR_SEND_INTERVAL     (SENSOR_SEND_INTERVAL_S * CLOCK_SECOND)

/*---------------------------------------------------------------------------*/
/* Energest (Energy Estimation)                                               */
/*---------------------------------------------------------------------------*/
#define ENERGEST_CONF_ON         1

/*---------------------------------------------------------------------------*/
/* Logging                                                                    */
/*---------------------------------------------------------------------------*/
#define LOG_CONF_LEVEL_RPL       LOG_LEVEL_WARN
#define LOG_CONF_LEVEL_TCPIP     LOG_LEVEL_WARN
#define LOG_CONF_LEVEL_IPV6      LOG_LEVEL_WARN
#define LOG_CONF_LEVEL_6LOWPAN   LOG_LEVEL_WARN

#endif /* PROJECT_CONF_H_ */
