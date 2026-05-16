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
/* How often the orchestrator shuffles IPv6 addresses (seconds).
 * Set to 2 minutes for the experimental evaluation: long enough to
 * leave room for reactive cycles to accumulate, short enough that a
 * 30-minute simulation produces ~15 cycles per run for statistics.
 * Production deployments would typically use 5-15 minutes. */
#define MTD_SHUFFLE_INTERVAL_S   120
#define MTD_SHUFFLE_INTERVAL     (MTD_SHUFFLE_INTERVAL_S * CLOCK_SECOND)

/* How often port hopping occurs (seconds).
 * Set to 5 minutes (2.5x the shuffle period) so the two proactive
 * timers stay asynchronous and an attacker observing one cannot
 * predict the other. */
#define MTD_PORT_HOP_INTERVAL_S  300
#define MTD_PORT_HOP_INTERVAL    (MTD_PORT_HOP_INTERVAL_S * CLOCK_SECOND)

/* Number of anomalies before triggering an immediate MTD response */
#define MTD_THREAT_THRESHOLD     5

/* Cooldown between successive reactive MTD cycles (thesis Sec 4.5.1,
 * Table 6). Prevents oscillation under a sustained attack and lets RPL
 * re-converge after a shuffle before a new one is initiated. */
#define MTD_COOLDOWN_S           60
#define MTD_COOLDOWN             (MTD_COOLDOWN_S * CLOCK_SECOND)

/* CPU load monitoring -- Energest-based flooding detection            */
#define MTD_CPU_THRESHOLD_PCT    80   /* CPU% above which flooding is inferred (thesis Sec 5.3.3) */
#define MTD_CPU_WINDOW_S         10   /* monitoring window length (seconds)    */
#define MTD_CPU_WINDOW           (MTD_CPU_WINDOW_S * CLOCK_SECOND)

/* Packet-rate proxy for flood detection.  On the Cooja contikimote target
 * ENERGEST_TYPE_LPM never accumulates, so the CPU% ratio is unusable.  As
 * a second, target-independent indicator we count UDP packets per rate
 * window; when the count exceeds this threshold within a single window
 * we report MTD_ANOMALY_CPU_LOAD (flooding).  A real Tmote-Sky build can
 * still rely on the Energest CPU% path in parallel.
 *
 * Threshold raised from 30 to 80 (per CPU_WINDOW_S=10s window, so 8 pkt/s)
 * so a 10 pkt/s scan does not also trip the flood branch.  Real flood
 * traffic at 20 pkt/s = 200 pkts/window comfortably exceeds 80. */
#define MTD_FLOOD_PPS_THRESHOLD  80   /* >80 pkts within MTD_CPU_WINDOW_S → flood */

/* Rate limiting -- application-layer packet cap per second.
 * Set to 10 pkt/s so the limiter actually engages during a 20-pkt/s
 * flood (with 25 legitimate sensors at ~2.5 pkt/s, total ~22.5 pkt/s
 * comfortably exceeds the cap).  Legitimate traffic stays below 10
 * during normal operation. */
#define MTD_RATE_LIMIT_PPS       10   /* max packets/s before dropping excess  */

/* Sensor-silence watchdog -- used to detect RPL sinkhole / routing disruption.
 * A registered sensor that has not transmitted for this many seconds is
 * flagged as a CONN_FAILURE anomaly.
 *
 * Set to 25s = 2.5 * SENSOR_SEND_INTERVAL_S (10s).  With CSMA fairness
 * the radio-disruption sinkhole approximation does not silence sensors
 * for 45s+ stretches; 25s is the smallest threshold that still rules
 * out single isolated packet losses (one missed send = 20s elapsed,
 * which stays under 25s).  Two consecutive missed sends = ~30s, well
 * over the threshold, which is the realistic sinkhole signature. */
#define MTD_SILENCE_TIMEOUT_S    25
#define MTD_SILENCE_TIMEOUT      (MTD_SILENCE_TIMEOUT_S * CLOCK_SECOND)
#define MTD_SILENCE_CHECK_S      15   /* watchdog poll interval */
#define MTD_SILENCE_CHECK        (MTD_SILENCE_CHECK_S * CLOCK_SECOND)

/* Post-shuffle grace window for the silence watchdog.  After every
 * shuffle, sensor registry slots keyed on the old address need a few
 * seconds to migrate; suppress the watchdog for that long so the
 * legitimate address migration is not mis-flagged as a sinkhole.
 * Must be SHORTER than the shuffle interval, otherwise the watchdog
 * is permanently muted (bug observed in early evaluation runs).
 *
 * Lowered from 20 s to 10 s after the sinkhole evaluation showed that
 * under a sustained STALE_PORT-dominated regime the reactive cycles
 * (cooldown 60 s) keep resetting the grace just before each 15 s
 * watchdog poll, starving the CONN_FAILURE branch.  Empirical sensor
 * address migration completes in 3-5 s, so a 10 s grace still safely
 * covers the legitimate migration window while letting the watchdog
 * fire between successive reactive cycles. */
#define MTD_SILENCE_GRACE_S      10
#define MTD_SILENCE_GRACE        (MTD_SILENCE_GRACE_S * CLOCK_SECOND)

/* Port hopping range: random port in [BASE, BASE + RANGE) */
#define MTD_BASE_PORT            5000
#define MTD_PORT_RANGE           1000

/*---------------------------------------------------------------------------*/
/* Attack scenario selector (thesis Chapter 5)                               */
/*---------------------------------------------------------------------------*/
/* attacker-node.c reads ATTACK_MODE at compile time.  Set from the .csc
 * make-command via DEFINES=ATTACK_MODE=<n>.  Default: IPv6 scan. */
#define ATTACK_MODE_SCAN         1   /* thesis Sec 5.3.1 -- ICMPv6 / UDP scan */
#define ATTACK_MODE_SINKHOLE     2   /* thesis Sec 5.3.2 -- RPL rank-1 spoof  */
#define ATTACK_MODE_FLOOD        3   /* thesis Sec 5.3.3 -- CoAP/UDP flood    */

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

/*---------------------------------------------------------------------------*/
/* TARGET=sky build: shrink the firmware to fit Tmote Sky's 48KB flash      */
/* and 10KB RAM.  These overrides are only applied when CONTIKI_TARGET_SKY   */
/* is defined, so the Cooja contikimote build keeps its full feature set.    */
/*---------------------------------------------------------------------------*/
#ifdef CONTIKI_TARGET_SKY

  /* uIP buffer: default is 1280B, way more than we need for plain UDP. */
  #define UIP_CONF_BUFFER_SIZE          240

  /* Neighbour and route tables: 30-node network, two hops max. */
  #define NBR_TABLE_CONF_MAX_NEIGHBORS  8
  #define UIP_CONF_MAX_ROUTES           8
  #define QUEUEBUF_CONF_NUM             4

  /* RPL features we don't need for evaluation. */
  #define RPL_CONF_WITH_PROBING         0
  #define RPL_CONF_WITH_DAO_ACK         0

  /* IPv6 reassembly costs ~3KB and we never send packets larger than the
   * uIP buffer, so disable it. */
  #define UIP_CONF_IPV6_REASSEMBLY      0

  /* The whole system uses UDP only.  Disabling TCP saves several KB
   * of code from the uIP stack. */
  #define UIP_CONF_TCP                  0

  /* Drop neighbour solicitation queueing; saves a small amount of RAM. */
  #define UIP_CONF_DS6_NBR_NBU          4

  /* Smaller default router and prefix tables. */
  #define UIP_CONF_DS6_DEFRT_NBU        1
  #define UIP_CONF_DS6_PREFIX_NBU       1

  /* Drop link-stats packet counters (debug only). */
  #define LINK_STATS_CONF_PACKET_COUNTERS 0

  /* Drop watchdog and stack-check helpers; not needed in simulation. */
  #define WATCHDOG_CONF_ENABLE          0
  #define STACK_CHECK_CONF_ENABLED      0

  /* Silence every Contiki-NG core module's logging.  The evaluation
   * parser only needs the structured log lines emitted by our own
   * modules (BorderRouter, SensorNode, MTDOrchestrator, IPv6Shuffle,
   * Attacker), which keep their own LOG_LEVEL.  Setting the rest to
   * NONE drops thousands of bytes of format strings. */
  #undef  LOG_CONF_LEVEL_RPL
  #undef  LOG_CONF_LEVEL_TCPIP
  #undef  LOG_CONF_LEVEL_IPV6
  #undef  LOG_CONF_LEVEL_6LOWPAN
  #define LOG_CONF_LEVEL_RPL            LOG_LEVEL_NONE
  #define LOG_CONF_LEVEL_TCPIP          LOG_LEVEL_NONE
  #define LOG_CONF_LEVEL_IPV6           LOG_LEVEL_NONE
  #define LOG_CONF_LEVEL_6LOWPAN        LOG_LEVEL_NONE
  #define LOG_CONF_LEVEL_MAC            LOG_LEVEL_NONE
  #define LOG_CONF_LEVEL_FRAMER         LOG_LEVEL_NONE
  #define LOG_CONF_LEVEL_MAIN           LOG_LEVEL_NONE

#endif /* CONTIKI_TARGET_SKY */

#endif /* PROJECT_CONF_H_ */
