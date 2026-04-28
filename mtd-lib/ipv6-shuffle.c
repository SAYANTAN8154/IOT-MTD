/*
 * ipv6-shuffle.c
 *
 * µMTD: IPv6 Interface Identifier (IID) randomisation.
 *
 * Implements the micro Moving Target Defense technique described in:
 *   Zeitz et al., "A Moving Target Defense for IoT Networks" (2017)
 *
 * How it works:
 *   - Every node has a link-local IPv6 address of the form fe80::/64 + IID
 *   - The /64 prefix is fixed by the network; only the lower 64 bits (IID)
 *     are under our control
 *   - This module replaces the IID with a cryptographically random value,
 *     making the node unreachable at its old address
 *   - The border router (orchestrator) triggers this on all nodes via RPL
 *     and distributes the new addresses so legitimate traffic can continue
 *
 * Thesis reference: System Design – Section 5.6 (IPv6 Address Shuffling)
 */

#include "contiki.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip.h"
#include "os/lib/random.h"
#include "sys/log.h"
#include "mtd-lib/ipv6-shuffle.h"

#include <string.h>
#include <stdint.h>

#define LOG_MODULE  "IPv6Shuffle"
#define LOG_LEVEL   LOG_LEVEL_INFO

/*---------------------------------------------------------------------------*/
/* Internal state                                                             */
/*---------------------------------------------------------------------------*/
static uip_ipaddr_t current_addr;   /* last shuffled address */
static uint32_t     shuffle_count = 0;

/*---------------------------------------------------------------------------*/
void
ipv6_shuffle_address(void)
{
  uip_ds6_addr_t *addr;
  uip_ipaddr_t    new_addr;

  /*
   * Find the node's current link-local unicast address (fe80::/64).
   * uip_ds6_get_link_local(-1) returns the first valid link-local entry.
   */
  addr = uip_ds6_get_link_local(-1);
  if(addr == NULL) {
    LOG_WARN("No link-local address found — shuffle aborted\n");
    return;
  }

  /* Copy the full current address so we keep the /64 prefix intact */
  uip_ip6addr_copy(&new_addr, &addr->ipaddr);

  /*
   * Overwrite the lower 64 bits (IID) with random values.
   * random_rand() returns a 16-bit value, so we call it four times.
   * Bit 6 of the first byte is cleared to mark it as globally unique
   * (RFC 4291 universal/local bit = 0 means locally administered here,
   *  which is appropriate for a randomly generated IID).
   */
  new_addr.u16[4] = random_rand();
  new_addr.u16[5] = random_rand();
  new_addr.u16[6] = random_rand();
  new_addr.u16[7] = random_rand();

  /* Clear the U/L bit in the IID (byte 8, bit 1) */
  new_addr.u8[8] &= ~0x02;

  LOG_INFO("Shuffle #%lu: old IID = %04x:%04x:%04x:%04x\n",
           (unsigned long)shuffle_count,
           UIP_HTONS(addr->ipaddr.u16[4]),
           UIP_HTONS(addr->ipaddr.u16[5]),
           UIP_HTONS(addr->ipaddr.u16[6]),
           UIP_HTONS(addr->ipaddr.u16[7]));

  /* Remove the old address from the DS6 table */
  uip_ds6_addr_rm(addr);

  /* Add the new randomised address as a manual (permanent) entry */
  uip_ds6_addr_add(&new_addr, 0, ADDR_MANUAL);

  /* Cache it and increment counter */
  uip_ip6addr_copy(&current_addr, &new_addr);
  shuffle_count++;

  LOG_INFO("Shuffle #%lu: new IID = %04x:%04x:%04x:%04x\n",
           (unsigned long)shuffle_count,
           UIP_HTONS(new_addr.u16[4]),
           UIP_HTONS(new_addr.u16[5]),
           UIP_HTONS(new_addr.u16[6]),
           UIP_HTONS(new_addr.u16[7]));
}

/*---------------------------------------------------------------------------*/
uint64_t
ipv6_shuffle_get_current_iid(void)
{
  uint64_t iid = 0;
  iid |= (uint64_t)UIP_HTONS(current_addr.u16[4]) << 48;
  iid |= (uint64_t)UIP_HTONS(current_addr.u16[5]) << 32;
  iid |= (uint64_t)UIP_HTONS(current_addr.u16[6]) << 16;
  iid |= (uint64_t)UIP_HTONS(current_addr.u16[7]);
  return iid;
}
/*---------------------------------------------------------------------------*/
