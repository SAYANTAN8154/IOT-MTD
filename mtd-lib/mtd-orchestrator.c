/*
 * mtd-orchestrator.c
 *
 * MTD Orchestrator -- runs on the border router (Class 2 device).
 *
 * Responsibilities:
 *   1. Proactive defence: trigger periodic IPv6 shuffles (every
 *      MTD_SHUFFLE_INTERVAL_S) and periodic port hops (every
 *      MTD_PORT_HOP_INTERVAL_S) on independent timers.
 *   2. Reactive defence: if anomaly reports exceed MTD_THREAT_THRESHOLD,
 *      trigger an immediate out-of-schedule shuffle + port hop and reset
 *      both timers so the attacker cannot predict the next cycle.
 *   3. Coordination: after each shuffle the orchestrator broadcasts
 *      CMD_ADDR_SHUFFLE (0x03) to every known sensor so they randomise
 *      their own IPv6 IID.  After each port hop it broadcasts
 *      CMD_PORT_HOP (0x01) carrying the new port value.
 *   4. Logging: print a structured MTD_CYCLE log line after every event
 *      so the evaluation script can measure shuffle latency and frequency.
 *
 * Port tracking:
 *   current_port tracks what active_port value sensor nodes SHOULD be
 *   reporting in their payloads.  It starts at SENSOR_UDP_CLIENT_PORT
 *   (the sensors' initial active_port) and changes on every port hop.
 *   border-router.c calls mtd_get_current_port() to perform the
 *   application-layer anomaly check on incoming packets.
 *
 * Thesis reference: System Design – Section 5.5 (MTD Orchestrator Design)
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/simple-udp.h"
#include "sys/ctimer.h"
#include "sys/energest.h"
#include "sys/log.h"
#include "lib/random.h"

#include "mtd-lib/ipv6-shuffle.h"
#include "mtd-lib/port-hopper.h"
#include "mtd-lib/mtd-orchestrator.h"
#include "project-conf.h"

#include <stdint.h>
#include <string.h>

#define LOG_MODULE  "MTDOrchestrator"
#define LOG_LEVEL   LOG_LEVEL_INFO

/*---------------------------------------------------------------------------*/
/* Command bytes -- keep in sync with sensor-node.c                           */
/*---------------------------------------------------------------------------*/
#define CMD_PORT_HOP      0x01   /* payload: 3 bytes (cmd + port hi + port lo) */
#define CMD_ADDR_SHUFFLE  0x03   /* payload: 1 byte  (cmd only)                */

/*---------------------------------------------------------------------------*/
/* Sensor address registry -- ring buffer                                      */
/*                                                                            */
/* RPL-Lite non-storing mode does not populate per-host downward routes on   */
/* the DAG root, so uip_ds6_route_head() is always empty here.  We maintain  */
/* an explicit ring buffer of the most recently seen sensor addresses.        */
/*                                                                            */
/* After each CMD_ADDR_SHUFFLE sensors change their IPv6 IID.  They send     */
/* their next data packet from the new address, which border-router.c         */
/* immediately passes to mtd_register_sensor().  The ring buffer evicts the   */
/* oldest entry when full, so stale post-shuffle addresses age out naturally  */
/* and the 64 slots always hold the most recently active addresses.           */
/*---------------------------------------------------------------------------*/
#define MTD_MAX_SENSORS  64   /* ring buffer capacity -- 2+ address generations */

static uip_ipaddr_t sensor_registry[MTD_MAX_SENSORS];
static uint8_t      sensor_count = 0;   /* entries written so far (≤ MTD_MAX_SENSORS) */
static uint8_t      sensor_head  = 0;   /* next write slot (wraps at MTD_MAX_SENSORS)  */

/* Per-sensor last-seen timestamps for the silence watchdog
 * (thesis Sec 5.3.2 -- RPL sinkhole detection).  Indexed in lock-step
 * with sensor_registry so sensor_last_seen[i] belongs to sensor_registry[i]. */
static clock_time_t sensor_last_seen[MTD_MAX_SENSORS];
/* Bit set when we have already reported a CONN_FAILURE for this slot in the
 * current silence episode -- cleared when the sensor transmits again. */
static uint8_t      sensor_silence_flagged[MTD_MAX_SENSORS];

/*---------------------------------------------------------------------------*/
/* Internal state                                                             */
/*---------------------------------------------------------------------------*/
static struct ctimer proactive_timer;   /* IPv6 shuffle timer                  */
static struct ctimer port_hop_timer;    /* independent port-hop timer          */
static uint8_t       anomaly_count = 0; /* total across all types              */
static uint32_t      cycle_count   = 0;

/*
 * Per-type anomaly counters -- used by the reactive handler to select the
 * appropriate MTD technique (see mtd_anomaly_type_t in mtd-orchestrator.h).
 */
static uint8_t anomaly_counts[MTD_ANOMALY_TYPE_COUNT];

/*---------------------------------------------------------------------------*/
/* CPU load monitoring                                                        */
/*---------------------------------------------------------------------------*/
/*
 * A ctimer fires every MTD_CPU_WINDOW_S seconds.  In the callback we read
 * Energest's cumulative CPU and LPM tick counters, compute the delta since
 * the last window, and derive a CPU load percentage:
 *
 *   cpu_load_pct = (delta_cpu * 100) / (delta_cpu + delta_lpm)
 *
 * If the result exceeds MTD_CPU_THRESHOLD_PCT a CPU_LOAD anomaly is reported,
 * which may trigger a reactive cycle selecting the flooding-defence branch
 * (shuffle + rate limiting).
 */
static struct ctimer  cpu_monitor_timer;
static uint64_t       cpu_prev     = 0;
static uint64_t       lpm_prev     = 0;
static uint8_t        cpu_load_pct = 0;   /* most recent window CPU% (0–100) */

/*---------------------------------------------------------------------------*/
/* Rate limiting                                                              */
/*---------------------------------------------------------------------------*/
/*
 * A 1-second rolling window counts incoming application-layer packets.
 * When cpu_load_pct > MTD_CPU_THRESHOLD_PCT (i.e. flooding is active),
 * mtd_rate_limit_check() returns 1 for any packet that would push the
 * per-second count above MTD_RATE_LIMIT_PPS.
 *
 * rate_limit_armed is set to 1 by the CPU monitor when flooding is detected
 * and cleared when cpu_load_pct drops back below the threshold.  This means
 * rate limiting is only enforced during an active flooding episode, not
 * permanently -- preventing unnecessary packet loss during normal operation.
 */
static struct ctimer  rate_window_timer;
static uint16_t       rate_window_count = 0;  /* packets seen this 1-s window */
static uint8_t        rate_limit_armed  = 0;  /* 1 = enforce PPS cap          */

/*---------------------------------------------------------------------------*/
/* Packet-rate flood monitor (Cooja-friendly CPU_LOAD proxy).                */
/*---------------------------------------------------------------------------*/
/* Counts packets over MTD_CPU_WINDOW_S.  If count > MTD_FLOOD_PPS_THRESHOLD
 * in a single window we raise MTD_ANOMALY_CPU_LOAD.  This is the primary
 * flood indicator on the Cooja contikimote target where LPM never
 * accumulates; on real hardware the Energest CPU% path below runs in
 * parallel and either may fire first. */
static struct ctimer  pkt_rate_timer;
static uint16_t       pkt_rate_window_count = 0;

/*---------------------------------------------------------------------------*/
/* Reactive cooldown (thesis Table 6, Sec 4.5.1)                             */
/*---------------------------------------------------------------------------*/
/* A reactive MTD cycle is only fired if at least MTD_COOLDOWN_S seconds have
 * elapsed since the previous one.  The threshold counter keeps accumulating
 * during cooldown so that the very next anomaly after the cooldown lifts
 * can trigger immediately -- matching the thesis description ("when any
 * single indicator exceeds its threshold AND the cooldown timer has
 * elapsed"). */
static clock_time_t   last_reactive_ts = 0;
static uint8_t        first_reactive   = 1;   /* allow the very first trigger */

/*---------------------------------------------------------------------------*/
/* Silence watchdog                                                          */
/*---------------------------------------------------------------------------*/
static struct ctimer  silence_timer;
/* After an address shuffle every sensor's previous address becomes stale
 * in the registry until the sensor re-registers with its new IID.  Suppress
 * the silence check until after this grace window to avoid spurious
 * CONN_FAILURE reports. */
static clock_time_t   silence_grace_until = 0;

/*
 * current_port  -- the port the orchestrator most recently broadcast.
 * previous_port -- the port from one hop ago.
 *
 * The anomaly check in border-router.c accepts both values so that a
 * sensor which missed exactly one CMD_PORT_HOP delivery is not falsely
 * flagged.  A sensor (or attacker) using a port two or more hops old
 * is still detected.
 *
 * Both start at SENSOR_UDP_CLIENT_PORT (8765) so no anomalies fire
 * before the first hop.
 */
static uint16_t current_port  = SENSOR_UDP_CLIENT_PORT;
static uint16_t previous_port = SENSOR_UDP_CLIENT_PORT;

/*
 * initial_grace_active -- while true, the anomaly check in border-router.c
 * also accepts SENSOR_UDP_CLIENT_PORT (8765) as a valid port so that sensors
 * that have not yet received their first CMD_PORT_HOP are not falsely flagged.
 *
 * The grace expires after the SECOND port hop (mtd_hop_count >= 2).  By that
 * point every actively transmitting sensor has received at least
 * 2 × MTD_PORT_HOP_INTERVAL_S / SENSOR_SEND_INTERVAL_S = 12 piggyback
 * port-update replies and is expected to be running a current MTD port.
 * After expiry, port 8765 is treated as an anomalous stale credential.
 */
static uint8_t  initial_grace_active = 1;
static uint8_t  mtd_hop_count            = 0;

/* UDP connection used to push commands down to sensor nodes */
static struct simple_udp_connection orchestrator_conn;

/*---------------------------------------------------------------------------*/
/* Forward declarations                                                       */
/*---------------------------------------------------------------------------*/
static void proactive_shuffle_cb(void *ptr);
static void port_hop_cb(void *ptr);
static void broadcast_port_update(uint16_t new_port);
static void broadcast_addr_shuffle(void);
static void cpu_monitor_cb(void *ptr);
static void rate_window_cb(void *ptr);
static void pkt_rate_cb(void *ptr);
static void silence_watchdog_cb(void *ptr);
static void reactive_shuffle_cb(void *ptr);

/*---------------------------------------------------------------------------*/
/*
 * broadcast_port_update -- unicast CMD_PORT_HOP to every registered sensor.
 *
 * Uses the sensor_registry built up by mtd_register_sensor() rather than
 * uip_ds6_route_head(), which is empty on the DAG root in RPL-Lite's
 * non-storing mode.
 *
 * Command layout (3 bytes):
 *   [0] = 0x01  (CMD_PORT_HOP)
 *   [1] = port >> 8
 *   [2] = port & 0xFF
 */
static void
broadcast_port_update(uint16_t new_port)
{
  uint8_t cmd[3];
  uint8_t i;
  int     rc;

  port_hopper_encode_cmd(cmd, new_port);

  if(sensor_count == 0) {
    LOG_INFO("CMD_PORT_HOP: no registered sensors yet (port=%u)\n", new_port);
    return;
  }

  for(i = 0; i < sensor_count; i++) {
    rc = simple_udp_sendto(&orchestrator_conn,
                           cmd, sizeof(cmd),
                           &sensor_registry[i]);
    if(rc < 0) {
      /* Unicast delivery failed -- routing disruption, count as CONN_FAILURE */
      LOG_WARN("CMD_PORT_HOP send failed (rc=%d) to ", rc);
      LOG_WARN_6ADDR(&sensor_registry[i]);
      LOG_WARN_("\n");
      mtd_report_anomaly_typed(MTD_ANOMALY_CONN_FAILURE);
    } else {
      LOG_INFO("Sent CMD_PORT_HOP (port=%u) to ", new_port);
      LOG_INFO_6ADDR(&sensor_registry[i]);
      LOG_INFO_("\n");
    }
  }
}

/*---------------------------------------------------------------------------*/
/*
 * broadcast_addr_shuffle -- unicast CMD_ADDR_SHUFFLE (0x03) to every
 * registered sensor so each one randomises its own IPv6 IID independently.
 *
 * Command layout (1 byte):
 *   [0] = 0x03  (CMD_ADDR_SHUFFLE)
 */
static void
broadcast_addr_shuffle(void)
{
  uint8_t cmd[1] = { CMD_ADDR_SHUFFLE };
  uint8_t i;
  int     rc;

  if(sensor_count == 0) {
    LOG_INFO("CMD_ADDR_SHUFFLE: no registered sensors yet\n");
    return;
  }

  for(i = 0; i < sensor_count; i++) {
    rc = simple_udp_sendto(&orchestrator_conn,
                           cmd, sizeof(cmd),
                           &sensor_registry[i]);
    if(rc < 0) {
      LOG_WARN("CMD_ADDR_SHUFFLE send failed (rc=%d) to ", rc);
      LOG_WARN_6ADDR(&sensor_registry[i]);
      LOG_WARN_("\n");
      mtd_report_anomaly_typed(MTD_ANOMALY_CONN_FAILURE);
    } else {
      LOG_INFO("Sent CMD_ADDR_SHUFFLE to ");
      LOG_INFO_6ADDR(&sensor_registry[i]);
      LOG_INFO_("\n");
    }
  }

  /*
   * Every sensor is about to change its IID, so its registry slot keyed
   * on the old address will not receive further traffic until the sensor
   * re-registers under its new address.  Suppress the silence watchdog
   * until the MTD_SILENCE_TIMEOUT window has passed so we don't mis-flag
   * the address migration as a sinkhole.
   */
  silence_grace_until = clock_time() + MTD_SILENCE_GRACE;
}

/*---------------------------------------------------------------------------*/
/*
 * proactive_shuffle_cb -- fires every MTD_SHUFFLE_INTERVAL.
 *
 * Actions:
 *   1. Shuffle the border router's own IPv6 IID.
 *   2. Broadcast CMD_ADDR_SHUFFLE so every sensor shuffles theirs.
 *   3. Reset the anomaly counter (proactive cycle clears the slate).
 */
static void
proactive_shuffle_cb(void *ptr)
{
  cycle_count++;
  LOG_INFO("=== MTD Shuffle Cycle #%lu (proactive) ===\n",
           (unsigned long)cycle_count);

  /* Shuffle this node's (BR) own IPv6 IID */
  ipv6_shuffle_address();

  /* Tell every sensor to shuffle their IID too */
  broadcast_addr_shuffle();

  /* Structured log line for evaluation script */
  LOG_INFO("MTD_CYCLE type=shuffle cycle=%lu port=%u\n",
           (unsigned long)cycle_count, current_port);

  /* NOTE: anomaly_count is NOT reset here.  The earlier implementation
   * cleared it on every proactive shuffle, which masked slow-firing
   * detectors (e.g. the CPU monitor at 10 s windows) from ever
   * reaching the threshold of 5.  The reactive cycle itself resets
   * the counters when it consumes a threshold breach (see
   * reactive_shuffle_cb), and the cooldown gate prevents oscillation. */

  ctimer_reset(&proactive_timer);
}

/*---------------------------------------------------------------------------*/
/*
 * port_hop_cb -- fires every MTD_PORT_HOP_INTERVAL (independent of shuffle).
 *
 * Actions:
 *   1. Pick a new random port via port_hopper_next().
 *   2. Update current_port so border-router.c anomaly checks reflect it.
 *   3. Broadcast CMD_PORT_HOP to all sensors.
 */
static void
port_hop_cb(void *ptr)
{
  cycle_count++;
  mtd_hop_count++;
  uint16_t new_port = port_hopper_next();
  previous_port = current_port;
  current_port  = new_port;

  /* Expire the 8765 initial-boot grace after the second hop.
   * Every active sensor has had >=120 s of piggyback replies by now. */
  if(initial_grace_active && mtd_hop_count >= 2) {
    initial_grace_active = 0;
    LOG_INFO("Initial port grace EXPIRED after hop %u -- port 8765 now anomalous\n",
             mtd_hop_count);
  }

  LOG_INFO("=== MTD Port Hop #%lu (proactive) port=%u ===\n",
           (unsigned long)cycle_count, current_port);

  broadcast_port_update(new_port);

  /* Structured log line for evaluation script */
  LOG_INFO("MTD_CYCLE type=port_hop cycle=%lu port=%u\n",
           (unsigned long)cycle_count, current_port);

  ctimer_reset(&port_hop_timer);
}

/*---------------------------------------------------------------------------*/
/*
 * reactive_shuffle_cb -- fires immediately when the anomaly threshold is hit.
 *
 * Threat-type selection logic:
 *   The orchestrator accumulates per-type anomaly counts (anomaly_counts[]).
 *   The type with the highest count determines the MTD response:
 *
 *   STALE_PORT dominant  → IPv6 IID shuffle only.
 *     Rationale: a scanning/replay attacker is using a stale port credential.
 *     Changing the address identity breaks ongoing reconnaissance without
 *     disrupting legitimate sensors that are already port-current.
 *
 *   CONN_FAILURE dominant → port hop only.
 *     Rationale: probing-induced routing disruption is causing delivery
 *     failures.  A fresh port re-establishes a clean logical channel while
 *     the address (and therefore RPL routes) remains stable.
 *
 *   CPU_LOAD dominant     → IPv6 IID shuffle + arm rate limiting.
 *     Rationale: flooding is saturating the CPU.  Changing the address
 *     forces the flood source to re-discover the target, buying time.
 *     Rate limiting (enforced by mtd_rate_limit_check in border-router.c)
 *     throttles excess traffic at the application layer until cpu_load_pct
 *     drops back below MTD_CPU_THRESHOLD_PCT.
 *
 * In all cases both proactive timers are restarted from the moment of the
 * reactive cycle so the attacker cannot predict the next scheduled hop.
 */
static void
reactive_shuffle_cb(void *ptr)
{
  cycle_count++;

  /* ---- Determine dominant threat type ---------------------------------- */
  /*
   * Severity-priority selection.  Rare-but-severe signals always win
   * over high-frequency noisy ones:
   *
   *   CONN_FAILURE   (silence -- real loss of network state)  -- highest
   *   CPU_LOAD       (sustained flood detected by packet rate)
   *   STALE_PORT     (replay / scan -- the default fallback)
   *
   * This replaces a pure "max count" rule that would otherwise let the
   * noisy STALE_PORT counter dominate even when a single severe event
   * triggered the reactive cycle.
   */
  mtd_anomaly_type_t threat;
  uint8_t t;
  if(anomaly_counts[MTD_ANOMALY_CONN_FAILURE] > 0) {
    threat = MTD_ANOMALY_CONN_FAILURE;
  } else if(anomaly_counts[MTD_ANOMALY_CPU_LOAD] > 0) {
    threat = MTD_ANOMALY_CPU_LOAD;
  } else {
    threat = MTD_ANOMALY_STALE_PORT;
  }

  LOG_INFO("=== MTD Reactive Cycle #%lu threshold=%u dominant=%u ===\n",
           (unsigned long)cycle_count, MTD_THREAT_THRESHOLD, (uint8_t)threat);

  /* ---- Select and apply MTD technique ---------------------------------- */
  /*
   * Only the timer consumed by this reactive action is rewound.  The other
   * timer is left alone so its existing countdown continues -- otherwise a
   * persistent attacker (anomaly threshold re-hit every ~25 s) would reset
   * both timers every cycle and the 60 s port hop would never fire.
   */
  switch(threat) {

    case MTD_ANOMALY_STALE_PORT:
      /*
       * Scanning / replay detected.
       * Shuffle the border router's own IID and command every sensor to do
       * the same.  No port hop -- the attacker is not yet controlling the
       * port channel.
       */
      ipv6_shuffle_address();
      broadcast_addr_shuffle();
      LOG_INFO("MTD_CYCLE type=reactive_shuffle cycle=%lu port=%u\n",
               (unsigned long)cycle_count, current_port);
      /* Shuffle consumed -- rewind shuffle timer, leave hop timer running */
      ctimer_set(&proactive_timer, MTD_SHUFFLE_INTERVAL,
                 proactive_shuffle_cb, NULL);
      break;

    case MTD_ANOMALY_CONN_FAILURE:
      /*
       * Routing / delivery disruption detected.
       * Perform an immediate port hop to re-establish a clean logical channel.
       * Address identity is left unchanged to keep RPL routes stable.
       */
      mtd_hop_count++;
      {
        uint16_t new_port = port_hopper_next();
        previous_port = current_port;
        current_port  = new_port;
        if(initial_grace_active && mtd_hop_count >= 2) {
          initial_grace_active = 0;
          LOG_INFO("Initial port grace EXPIRED (reactive/conn hop %u)\n",
                   mtd_hop_count);
        }
        broadcast_port_update(new_port);
        LOG_INFO("MTD_CYCLE type=reactive_hop cycle=%lu port=%u\n",
                 (unsigned long)cycle_count, current_port);
      }
      /* Port hop consumed -- rewind hop timer, leave shuffle timer running */
      ctimer_set(&port_hop_timer, MTD_PORT_HOP_INTERVAL,
                 port_hop_cb, NULL);
      break;

    case MTD_ANOMALY_CPU_LOAD:
      /*
       * Flooding detected -- CPU load exceeded MTD_CPU_THRESHOLD_PCT.
       * Shuffle the address to force the flood source to re-discover the
       * target, then arm the rate limiter so mtd_rate_limit_check() starts
       * dropping excess traffic.  The rate limiter stays armed until the
       * CPU monitor confirms load has dropped below the threshold.
       */
      ipv6_shuffle_address();
      broadcast_addr_shuffle();
      rate_limit_armed = 1;
      LOG_INFO("MTD_CYCLE type=reactive_flood cycle=%lu port=%u "
               "rate_limit=ARMED\n",
               (unsigned long)cycle_count, current_port);
      /* Shuffle consumed -- rewind shuffle timer, leave hop timer running */
      ctimer_set(&proactive_timer, MTD_SHUFFLE_INTERVAL,
                 proactive_shuffle_cb, NULL);
      break;

    default:
      break;
  }

  /* ---- Reset counters -------------------------------------------------- */
  anomaly_count = 0;
  for(t = 0; t < MTD_ANOMALY_TYPE_COUNT; t++) {
    anomaly_counts[t] = 0;
  }
}

/*---------------------------------------------------------------------------*/
/*
 * cpu_monitor_cb -- fires every MTD_CPU_WINDOW_S seconds.
 *
 * Reads the cumulative Energest CPU and LPM counters, computes the
 * fraction of the last window spent in active CPU mode, and stores the
 * result in cpu_load_pct.  If the load exceeds MTD_CPU_THRESHOLD_PCT a
 * CPU_LOAD anomaly is reported, which may trigger the flooding-defence
 * reactive branch.  When the load falls back below the threshold the rate
 * limiter is disarmed so normal throughput resumes.
 */
static void
cpu_monitor_cb(void *ptr)
{
  uint64_t cpu_now, lpm_now, delta_cpu, delta_lpm, total;

  energest_flush();
  cpu_now = energest_type_time(ENERGEST_TYPE_CPU);
  lpm_now = energest_type_time(ENERGEST_TYPE_LPM);

  delta_cpu = cpu_now - cpu_prev;
  delta_lpm = lpm_now - lpm_prev;
  total     = delta_cpu + delta_lpm;

  cpu_prev = cpu_now;
  lpm_prev = lpm_now;

  /*
   * Cooja's native-mote target does not model low-power sleep, so
   * ENERGEST_TYPE_LPM never accumulates and delta_lpm is always 0.
   * Treating that as "100% CPU load" would fire a spurious flooding
   * anomaly every window.  Require a non-zero LPM delta before we
   * trust the ratio; otherwise mark it unmeasurable and skip the check.
   * On real Tmote-Sky hardware LPM ticks accumulate normally, so this
   * guard is a no-op there.
   */
  if(delta_lpm == 0 || total == 0) {
    LOG_INFO("CPU_MONITOR load=unavailable (no LPM signal on this target)\n");
    ctimer_reset(&cpu_monitor_timer);
    return;
  }

  cpu_load_pct = (uint8_t)((delta_cpu * 100) / total);

  LOG_INFO("CPU_MONITOR load=%u%% (threshold=%u%%)\n",
           cpu_load_pct, MTD_CPU_THRESHOLD_PCT);

  if(cpu_load_pct > MTD_CPU_THRESHOLD_PCT) {
    LOG_WARN("CPU load %u%% exceeds threshold -- reporting flooding anomaly\n",
             cpu_load_pct);
    mtd_report_anomaly_typed(MTD_ANOMALY_CPU_LOAD);
  }
  /*
   * NOTE: the rate limiter is no longer disarmed here.  On the Sky target
   * the CPU% reading stays low (4-18%) even during a heavy flood because
   * MSPSim runs the radio path very efficiently, so disarming based on
   * cpu_load_pct < threshold immediately undoes the limiter every window
   * even while the flood is still active.  Disarming is now driven by
   * the packet-rate proxy (pkt_rate_cb) which is the true flood signal
   * on this target.
   */

  ctimer_reset(&cpu_monitor_timer);
}

/*---------------------------------------------------------------------------*/
/*
 * rate_window_cb -- fires every CLOCK_SECOND to reset the per-second
 * packet counter used by mtd_rate_limit_check().
 */
static void
rate_window_cb(void *ptr)
{
  rate_window_count = 0;
  ctimer_reset(&rate_window_timer);
}

/*---------------------------------------------------------------------------*/
/*
 * pkt_rate_cb -- fires every MTD_CPU_WINDOW_S seconds.
 *
 * Packet-rate flood detector.  On the Cooja contikimote target the
 * Energest LPM counter never increments, so cpu_monitor_cb() cannot
 * compute a CPU% ratio.  This callback provides a target-independent
 * flood indicator: if the observed packet count within the monitoring
 * window exceeds MTD_FLOOD_PPS_THRESHOLD, a CPU_LOAD anomaly is
 * reported -- mapped by the technique-selection logic (thesis Sec 4.5.2)
 * to the composite "IPv6 shuffle + rate limit" response.
 *
 * Thesis reference: Sec 5.3.3 (CoAP flooding scenario).
 */
static void
pkt_rate_cb(void *ptr)
{
  uint16_t count = pkt_rate_window_count;
  pkt_rate_window_count = 0;

  LOG_INFO("PKT_RATE count=%u window=%ds threshold=%u\n",
           count, MTD_CPU_WINDOW_S, MTD_FLOOD_PPS_THRESHOLD);

  if(count > MTD_FLOOD_PPS_THRESHOLD) {
    LOG_WARN("Packet rate %u/%ds exceeds threshold %u -- reporting flooding anomaly\n",
             count, MTD_CPU_WINDOW_S, MTD_FLOOD_PPS_THRESHOLD);
    mtd_report_anomaly_typed(MTD_ANOMALY_CPU_LOAD);
  } else if(rate_limit_armed) {
    /*
     * Packet rate has dropped back below the flood threshold AND
     * rate-limit branch was active.  This is the correct disarm
     * condition: the actual flood signal (packet rate) has subsided,
     * not just the CPU% reading.  Limiter self-clears so normal
     * traffic resumes without manual intervention.
     */
    rate_limit_armed = 0;
    LOG_INFO("Packet rate nominal -- rate limiter DISARMED\n");
  }

  ctimer_reset(&pkt_rate_timer);
}

/*---------------------------------------------------------------------------*/
/*
 * silence_watchdog_cb -- fires every MTD_SILENCE_CHECK_S seconds.
 *
 * Per-sensor sinkhole detector.  When a RPL sinkhole attacker hijacks a
 * legitimate sensor's upward path (thesis Sec 5.3.2), the sensor's packets
 * no longer reach the border router even though the sensor is still
 * transmitting.  From the orchestrator's point of view that sensor has
 * "gone silent" even though earlier packets registered it.
 *
 * We iterate the sensor registry and flag any entry whose last-seen
 * timestamp is older than MTD_SILENCE_TIMEOUT as CONN_FAILURE.  Each slot
 * is flagged at most once per silence episode (sensor_silence_flagged[i])
 * so a permanently dropped node does not produce a flood of anomalies.
 * The flag is cleared by mtd_register_sensor() when the sensor reappears.
 *
 * The per-type counter maps to the CONN_FAILURE technique branch
 * (reactive port hop), consistent with "service-level probing and
 * selective forwarding → port hopping" from thesis Sec 4.5.2.
 */
static void
silence_watchdog_cb(void *ptr)
{
  clock_time_t now = clock_time();
  uint8_t i;
  uint8_t valid = (sensor_count < MTD_MAX_SENSORS) ? sensor_count
                                                    : MTD_MAX_SENSORS;

  if(silence_grace_until != 0 && now < silence_grace_until) {
    LOG_INFO("SILENCE watchdog skipped (post-shuffle grace %lus left)\n",
             (unsigned long)((silence_grace_until - now) / CLOCK_SECOND));
    ctimer_reset(&silence_timer);
    return;
  }

  for(i = 0; i < valid; i++) {
    if(sensor_silence_flagged[i]) {
      continue;   /* already flagged in this silence episode */
    }
    if(sensor_last_seen[i] == 0) {
      continue;   /* never seen a packet yet -- not a silence */
    }
    if((now - sensor_last_seen[i]) >= MTD_SILENCE_TIMEOUT) {
      LOG_WARN("SILENCE sensor #%u idle %lus (>%ds) -- CONN_FAILURE ",
               i,
               (unsigned long)((now - sensor_last_seen[i]) / CLOCK_SECOND),
               MTD_SILENCE_TIMEOUT_S);
      LOG_WARN_6ADDR(&sensor_registry[i]);
      LOG_WARN_("\n");
      sensor_silence_flagged[i] = 1;
      mtd_report_anomaly_typed(MTD_ANOMALY_CONN_FAILURE);
    }
  }

  ctimer_reset(&silence_timer);
}

/*---------------------------------------------------------------------------*/
/* Public API                                                                 */
/*---------------------------------------------------------------------------*/

void
mtd_orchestrator_init(void)
{
  uint8_t t;

#ifndef CONTIKI_TARGET_SKY
  /* Startup banner -- skipped on Sky to save ~300B of Flash. */
  LOG_INFO("MTD Orchestrator starting...\n");
  LOG_INFO("  Shuffle interval  : %d s\n", MTD_SHUFFLE_INTERVAL_S);
  LOG_INFO("  Port hop interval : %d s\n", MTD_PORT_HOP_INTERVAL_S);
  LOG_INFO("  Threat threshold  : %d anomalies\n", MTD_THREAT_THRESHOLD);
  LOG_INFO("  CPU threshold     : %d%%\n", MTD_CPU_THRESHOLD_PCT);
  LOG_INFO("  CPU window        : %d s\n", MTD_CPU_WINDOW_S);
  LOG_INFO("  Rate limit        : %d pkt/s\n", MTD_RATE_LIMIT_PPS);
#endif

  /* Zero per-type anomaly counters */
  for(t = 0; t < MTD_ANOMALY_TYPE_COUNT; t++) {
    anomaly_counts[t] = 0;
  }

  /* Initialise sub-modules */
  port_hopper_init();

  /*
   * Register UDP connection for sending commands to sensor nodes.
   * Source port = SENSOR_UDP_SERVER_PORT (5678, the BR's identity).
   * Destination port = SENSOR_UDP_CLIENT_PORT (8765, sensors listen there).
   */
  simple_udp_register(&orchestrator_conn,
                      SENSOR_UDP_SERVER_PORT,
                      NULL,
                      SENSOR_UDP_CLIENT_PORT,
                      NULL);   /* no receive callback needed on orchestrator */

  /* current_port starts at SENSOR_UDP_CLIENT_PORT -- the initial active_port
   * that all sensors use before the first CMD_PORT_HOP arrives.            */
  current_port = SENSOR_UDP_CLIENT_PORT;

  /* Arm the two independent proactive timers */
  ctimer_set(&proactive_timer, MTD_SHUFFLE_INTERVAL,
             proactive_shuffle_cb, NULL);

  ctimer_set(&port_hop_timer, MTD_PORT_HOP_INTERVAL,
             port_hop_cb, NULL);

  /*
   * Seed Energest baselines and start the CPU monitoring timer.
   * The first window starts from NOW so the first sample reflects real
   * load rather than the entire uptime since boot.
   */
  energest_flush();
  cpu_prev = energest_type_time(ENERGEST_TYPE_CPU);
  lpm_prev = energest_type_time(ENERGEST_TYPE_LPM);
  ctimer_set(&cpu_monitor_timer, MTD_CPU_WINDOW, cpu_monitor_cb, NULL);

  /* Start the 1-second rate-limit window reset timer */
  ctimer_set(&rate_window_timer, CLOCK_SECOND, rate_window_cb, NULL);

  /* Packet-rate flood monitor (CPU_LOAD proxy for Cooja contikimote) */
  ctimer_set(&pkt_rate_timer, MTD_CPU_WINDOW, pkt_rate_cb, NULL);

  /* Sensor-silence watchdog (CONN_FAILURE detection for sinkhole attacks) */
  ctimer_set(&silence_timer, MTD_SILENCE_CHECK, silence_watchdog_cb, NULL);

#ifndef CONTIKI_TARGET_SKY
  LOG_INFO("MTD Orchestrator ready. shuffle=%ds hop=%ds cpu_win=%ds "
           "cooldown=%ds flood_pps=%u silence=%ds\n",
           MTD_SHUFFLE_INTERVAL_S, MTD_PORT_HOP_INTERVAL_S, MTD_CPU_WINDOW_S,
           MTD_COOLDOWN_S, MTD_FLOOD_PPS_THRESHOLD, MTD_SILENCE_TIMEOUT_S);
#endif
}

/*---------------------------------------------------------------------------*/
void
mtd_report_anomaly_typed(mtd_anomaly_type_t type)
{
  if(type >= MTD_ANOMALY_TYPE_COUNT) {
    return;   /* guard against out-of-range values */
  }

  anomaly_counts[type]++;
  anomaly_count++;

  LOG_INFO("Anomaly type=%u count=%u/%u\n",
           (uint8_t)type, anomaly_count, MTD_THREAT_THRESHOLD);

  /*
   * Per-type firing policy.  STALE_PORT is a noisy high-frequency signal
   * (legitimate sensors falling one or two hops behind during heavy
   * reactive activity), so it requires accumulation to MTD_THREAT_THRESHOLD
   * before firing.  CONN_FAILURE and CPU_LOAD are rare-but-severe signals
   * (each event represents a real deviation: a missing sensor or a
   * sustained packet-rate flood), so they fire reactive immediately on the
   * first event.  Without this distinction, the noisy STALE_PORT counter
   * always wins the dominant-type race and the CONN_FAILURE / CPU_LOAD
   * branches are unreachable in practice.
   */
  uint8_t severe = (type == MTD_ANOMALY_CONN_FAILURE ||
                    type == MTD_ANOMALY_CPU_LOAD);

  if(severe || anomaly_count >= MTD_THREAT_THRESHOLD) {
    /*
     * Cooldown gate (thesis Sec 4.5.1 / Table 6).  A reactive cycle is
     * only fired if MTD_COOLDOWN_S seconds have elapsed since the last
     * one -- this prevents oscillation under sustained attacks and lets
     * RPL re-converge after each shuffle.  The counters keep accumulating
     * during cooldown so the very next anomaly after cooldown expiry
     * still triggers immediately.
     */
    clock_time_t now = clock_time();
    if(!first_reactive &&
       (now - last_reactive_ts) < MTD_COOLDOWN) {
      LOG_INFO("Threat threshold reached but cooldown active "
               "(%lu/%lu s remaining) -- reactive trigger suppressed\n",
               (unsigned long)((MTD_COOLDOWN - (now - last_reactive_ts))
                               / CLOCK_SECOND),
               (unsigned long)MTD_COOLDOWN_S);
      return;
    }

    LOG_WARN("Threat threshold reached -- triggering reactive MTD cycle\n");
    last_reactive_ts = now;
    first_reactive   = 0;

    /*
     * Fire reactive callback immediately (delay = 0).  The callback itself
     * rewinds only the timer whose action it consumed (shuffle OR hop), so
     * a persistent attacker cannot starve the unconsumed proactive timer.
     */
    static struct ctimer reactive_timer;
    ctimer_set(&reactive_timer, 0, reactive_shuffle_cb, NULL);
  }
}

/*---------------------------------------------------------------------------*/
/*
 * mtd_report_anomaly -- backward-compatible wrapper.
 * Reports MTD_ANOMALY_STALE_PORT (scanning / replay).
 * Existing call sites in border-router.c continue to compile unchanged.
 */
void
mtd_report_anomaly(void)
{
  mtd_report_anomaly_typed(MTD_ANOMALY_STALE_PORT);
}

/*---------------------------------------------------------------------------*/
uint16_t
mtd_get_current_port(void)
{
  return current_port;
}

/*---------------------------------------------------------------------------*/
uint16_t
mtd_get_previous_port(void)
{
  return previous_port;
}

/*---------------------------------------------------------------------------*/
uint8_t
mtd_initial_grace_active(void)
{
  return initial_grace_active;
}

/*---------------------------------------------------------------------------*/
/*
 * mtd_rate_limit_check -- called by border-router.c for every arriving packet.
 *
 * When rate_limit_armed is 0 (no flooding detected) every packet is accepted.
 * When armed, the rolling per-second counter is incremented; if it exceeds
 * MTD_RATE_LIMIT_PPS the function returns 1 and the caller drops the packet
 * without processing it.
 *
 * The window counter is reset to 0 every CLOCK_SECOND by rate_window_cb().
 *
 * Returns: 0 = accept, 1 = drop.
 */
uint8_t
mtd_rate_limit_check(void)
{
  if(!rate_limit_armed) {
    return 0;   /* rate limiting not active -- accept all packets */
  }

  rate_window_count++;
  if(rate_window_count > MTD_RATE_LIMIT_PPS) {
    LOG_WARN("RATE_LIMIT drop pkt (count=%u limit=%u)\n",
             rate_window_count, MTD_RATE_LIMIT_PPS);
    return 1;   /* drop -- window saturated */
  }
  return 0;
}

/*---------------------------------------------------------------------------*/
/*
 * mtd_flood_active -- non-zero while the CPU_LOAD branch is still mitigating
 * a flood (rate limiter armed).  The CPU monitor clears rate_limit_armed
 * automatically when the load drops back below MTD_CPU_THRESHOLD_PCT, so
 * this also self-clears.
 */
uint8_t
mtd_flood_active(void)
{
  return rate_limit_armed;
}

/*---------------------------------------------------------------------------*/
/*
 * mtd_send_port_update -- send a CMD_PORT_HOP reply directly to one sensor.
 *
 * Called from border-router.c immediately after a valid upward packet arrives.
 * The IP stack still holds a fresh reverse-route entry from the just-received
 * packet, so this downward send succeeds even in RPL-Lite non-storing mode
 * where proactive downward routes are not maintained.
 *
 * Only sends when at least one hop has fired (current_port != initial port)
 * so we never flood sensors with redundant 8765 updates before MTD starts.
 */
void
mtd_send_port_update(const uip_ipaddr_t *addr)
{
  uint8_t cmd[3];

  if(current_port == SENSOR_UDP_CLIENT_PORT) {
    return;   /* MTD not started yet -- nothing useful to send */
  }

  port_hopper_encode_cmd(cmd, current_port);
  simple_udp_sendto(&orchestrator_conn, cmd, sizeof(cmd), addr);
}

/*---------------------------------------------------------------------------*/
/*
 * mtd_register_sensor -- add a sensor's IPv6 address to the registry.
 *
 * Called by border-router.c from its UDP receive callback every time a
 * valid data packet arrives.  Duplicate addresses are silently ignored.
 * The registry is capped at MTD_MAX_SENSORS (32) entries.
 */
void
mtd_register_sensor(const uip_ipaddr_t *addr)
{
  uint8_t i;
  clock_time_t now = clock_time();
  uint8_t check_count = (sensor_count < MTD_MAX_SENSORS) ? sensor_count : MTD_MAX_SENSORS;

  /* Check for duplicate in the currently valid portion of the ring */
  for(i = 0; i < check_count; i++) {
    if(uip_ipaddr_cmp(&sensor_registry[i], addr)) {
      /* Already known -- refresh last-seen and clear any silence flag */
      if(sensor_silence_flagged[i]) {
        LOG_INFO("SILENCE recovered sensor #%u (silence ended)\n", i);
      }
      sensor_last_seen[i]      = now;
      sensor_silence_flagged[i] = 0;
      return;
    }
  }

  /* Write into the next ring slot (overwrites oldest entry when full) */
  uip_ipaddr_copy(&sensor_registry[sensor_head], addr);
  sensor_last_seen[sensor_head]       = now;
  sensor_silence_flagged[sensor_head] = 0;

  if(sensor_count < MTD_MAX_SENSORS) {
    sensor_count++;
    LOG_INFO("Registered sensor #%u: ", sensor_count);
  } else {
    LOG_INFO("Registry ring: replaced slot %u with ", sensor_head);
  }
  LOG_INFO_6ADDR(addr);
  LOG_INFO_("\n");

  sensor_head = (sensor_head + 1) % MTD_MAX_SENSORS;
}

/*---------------------------------------------------------------------------*/
/*
 * mtd_packet_rate_tick -- called once per incoming application-layer packet
 * at the border router.  Feeds the CPU_LOAD flood proxy (pkt_rate_cb).
 *
 * Thesis reference: Sec 5.3.3 (CoAP flooding scenario).  On Cooja the
 * Energest LPM counter does not accumulate, so the CPU% ratio is not
 * usable; this packet-rate counter is the practical flood indicator for
 * the contikimote target.  On real hardware the two detectors run in
 * parallel and either can fire a flood anomaly first.
 */
void
mtd_packet_rate_tick(void)
{
  if(pkt_rate_window_count < 0xFFFF) {
    pkt_rate_window_count++;
  }
}
/*---------------------------------------------------------------------------*/
