#ifndef PORT_HOPPER_H_
#define PORT_HOPPER_H_

#include <stdint.h>

/*---------------------------------------------------------------------------*/
/* Port Hopper API                                                            */
/*---------------------------------------------------------------------------*/

/**
 * Initialise the port hopper.
 * Sets the active port to MTD_BASE_PORT.
 * Call once from mtd-orchestrator.c at startup.
 */
void port_hopper_init(void);

/**
 * Generate a new random port in [MTD_BASE_PORT, MTD_BASE_PORT + MTD_PORT_RANGE)
 * Updates the internal active port and returns it.
 * Called by the orchestrator at each MTD port-hop cycle.
 */
uint16_t port_hopper_next(void);

/**
 * Return the currently active port without changing it.
 * Used by sensor-node.c to tag outgoing packets with the right port.
 */
uint16_t port_hopper_current(void);

/**
 * Encode the new port into a 3-byte command buffer ready to send over UDP.
 * Format: [ CMD_PORT_HOP (0x01) | port_hi | port_lo ]
 * buf must be at least 3 bytes.
 */
void port_hopper_encode_cmd(uint8_t *buf, uint16_t port);

#endif /* PORT_HOPPER_H_ */
