CONTIKI_PROJECT = sensor-node border-router border-router-nomtd \
                  attacker-scan attacker-sinkhole attacker-flood

all: $(CONTIKI_PROJECT)

CONTIKI = /home/stan/project/contiki-ng

# MTD implementation files are unity-built directly into border-router.c
# and sensor-node.c via #include directives (see those files).
# No MODULES_REL or PROJECT_SOURCEFILES needed.
#
# Attack scenario selector (thesis Chapter 5): attacker-node.c implements
# all three attack behaviours under the ATTACK_MODE compile-time switch.
# Each mode is built as an independent firmware via a thin wrapper file
# (attacker-scan.c / attacker-sinkhole.c / attacker-flood.c), each of
# which #defines ATTACK_MODE and #includes attacker-node.c.  This gives
# three distinct .cooja binaries that Make tracks independently, so
# switching scenarios never reuses a stale attacker object file.
#
#   attacker-scan.cooja      ATTACK_MODE=1  IPv6 scan      (Sec 5.3.1)
#   attacker-sinkhole.cooja  ATTACK_MODE=2  RPL sinkhole   (Sec 5.3.2)
#   attacker-flood.cooja     ATTACK_MODE=3  CoAP/UDP flood (Sec 5.3.3)
#
# The corresponding .csc files reference the right wrapper; no DEFINES=
# argument is needed on the make command line.

# Enable Energest for energy measurements
MAKE_WITH_ENERGEST = 1

# Enable RPL
MAKE_WITH_RPL = 1

# Tmote Sky has only 48KB flash and 10KB RAM.  The default Contiki-NG
# build does not optimise for size, which pushes the unity-built MTD
# firmware over the flash limit.  Enable -Os and dead-code/-data
# elimination ONLY for TARGET=sky so the contikimote build is unaffected.
ifeq ($(TARGET),sky)
  CFLAGS  += -Os -ffunction-sections -fdata-sections
  LDFLAGS += -Wl,--gc-sections
endif

include $(CONTIKI)/Makefile.include
