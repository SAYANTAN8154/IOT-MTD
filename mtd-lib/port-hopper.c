/*
 * port-hopper.c
 *
 * MTD Port Hopping module.
 *
 * Implements the port hopping technique as a complementary MTD layer
 * alongside IPv6 address shuffling. Port hopping changes the UDP
 * communication port used by all sensor nodes on a periodic basis,
 * invalidating any attacker intelligence about which port to target.
 *
 * Design:
 *   - The orchestrator (border router) calls port_hopper_next() at each
 *     hop interval to get a new random port.
 *   - It then broadcasts a CMD_PORT_HOP command to every sensor node,
 *     carrying the new port as a 2-byte big-endian payload.
 *   - Sensor nodes update their active_port variable and use it for
 *     all subsequent outgoing packets.
 *   - The old port remains "registered" in simple-udp (no unregister API),
 *     but since the orchestrator stops listening on it, stale traffic is
 *     silently dropped.
 *
 * Port selection:
 *   - Random draw from [MTD_BASE_PORT, MTD_BASE_PORT + MTD_PORT_RANGE)
 *   - The same port is never repeated twice in a row (collision check)
 *   - Ports below 1024 (well-known) are never selected
 *
 * Thesis reference: System Design – Section 5.7 (Port Hopping)
 */

#include "contiki.h"
#include "lib/random.h"
#include "sys/log.h"
#include "mtd-lib/port-hopper.h"
#include "project-conf.h"

#include <stdint.h>
#include <string.h>

#define LOG_MODULE  "PortHopper"
#define LOG_LEVEL   LOG_LEVEL_INFO

/*---------------------------------------------------------------------------*/
/* Internal state                                                             */
/*---------------------------------------------------------------------------*/
static uint16_t active_port  = MTD_BASE_PORT;
static uint16_t prev_port    = 0;
static uint32_t hop_count    = 0;

/*---------------------------------------------------------------------------*/
void
port_hopper_init(void)
{
  active_port = MTD_BASE_PORT;
  prev_port   = 0;
  hop_count   = 0;
  LOG_INFO("Port hopper initialised. Base port: %u, range: %u\n",
           MTD_BASE_PORT, MTD_PORT_RANGE);
}

/*---------------------------------------------------------------------------*/
uint16_t
port_hopper_next(void)
{
  uint16_t new_port;
  uint8_t  attempts = 0;

  /*
   * Draw a random port, re-rolling if:
   *   (a) it equals the previous port (no immediate repeats), or
   *   (b) it falls below 1024 (well-known port range).
   * Cap at 10 attempts to avoid an infinite loop; fall back to
   * BASE_PORT + 1 in the degenerate case.
   */
  do {
    new_port = MTD_BASE_PORT + (random_rand() % MTD_PORT_RANGE);
    attempts++;
  } while((new_port == prev_port || new_port < 1024) && attempts < 10);

  if(attempts >= 10) {
    new_port = MTD_BASE_PORT + 1;
    LOG_WARN("Port selection fallback after %u attempts\n", attempts);
  }

  prev_port   = active_port;
  active_port = new_port;
  hop_count++;

  LOG_INFO("Hop #%lu: port %u -> %u\n",
           (unsigned long)hop_count, prev_port, active_port);

  return active_port;
}

/*---------------------------------------------------------------------------*/
uint16_t
port_hopper_current(void)
{
  return active_port;
}

/*---------------------------------------------------------------------------*/
void
port_hopper_encode_cmd(uint8_t *buf, uint16_t port)
{
  /*
   * Command layout (3 bytes):
   *   buf[0] = 0x01  (CMD_PORT_HOP, matches sensor-node.c definition)
   *   buf[1] = port >> 8   (high byte, big-endian)
   *   buf[2] = port & 0xFF (low byte)
   */
  buf[0] = 0x01;
  buf[1] = (uint8_t)(port >> 8);
  buf[2] = (uint8_t)(port & 0xFF);
}
/*---------------------------------------------------------------------------*/
