#ifndef IPV6_SHUFFLE_H_
#define IPV6_SHUFFLE_H_

#include "contiki.h"
#include "net/ipv6/uip.h"

/*---------------------------------------------------------------------------*/
/* IPv6 Address Shuffling (µMTD) API                                         */
/*---------------------------------------------------------------------------*/

/**
 * Randomise the Interface Identifier (IID) of this node's link-local
 * IPv6 address while keeping the /64 prefix unchanged.
 * This implements the µMTD technique described in Zeitz et al. (2017).
 */
void ipv6_shuffle_address(void);

/**
 * Get the current IID as a 64-bit value (for logging/reporting).
 */
uint64_t ipv6_shuffle_get_current_iid(void);

#endif /* IPV6_SHUFFLE_H_ */
