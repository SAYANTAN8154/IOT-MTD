#!/usr/bin/env python3
"""
convert_to_sky.py

Generates TARGET=sky variants of every existing TARGET=cooja .csc file.
The Sky variant uses the MSPSim emulator, which produces accurate Energest
counters (real LPM, CPU, TX, RX ticks) instead of the contikimote target's
LPM=0 limitation.

Output: <name>_sky.csc placed alongside the original.
"""
import re
import sys
from pathlib import Path

# Full set of <moteinterface> entries needed by the Sky/MSPSim target.
SKY_INTERFACES = [
    "org.contikios.cooja.interfaces.Position",
    "org.contikios.cooja.interfaces.RimeAddress",
    "org.contikios.cooja.interfaces.IPAddress",
    "org.contikios.cooja.interfaces.Mote2MoteRelations",
    "org.contikios.cooja.interfaces.MoteAttributes",
    "org.contikios.cooja.mspmote.interfaces.MspClock",
    "org.contikios.cooja.mspmote.interfaces.MspMoteID",
    "org.contikios.cooja.mspmote.interfaces.SkyButton",
    "org.contikios.cooja.mspmote.interfaces.SkyFlash",
    "org.contikios.cooja.mspmote.interfaces.SkyCoffeeFilesystem",
    "org.contikios.cooja.mspmote.interfaces.Msp802154Radio",
    "org.contikios.cooja.mspmote.interfaces.MspDefaultSerial",
    "org.contikios.cooja.mspmote.interfaces.SkyLED",
    "org.contikios.cooja.mspmote.interfaces.MspDebugOutput",
    "org.contikios.cooja.mspmote.interfaces.SkyTemperature",
]


def convert(text: str) -> str:
    # 1. motetype class (exact match, package path preserved)
    text = text.replace(
        "org.contikios.cooja.contikimote.ContikiMoteType",
        "org.contikios.cooja.mspmote.SkyMoteType",
    )

    # 2. ContikiMoteID -> MspMoteID inside <interface_config>
    text = text.replace(
        "org.contikios.cooja.contikimote.interfaces.ContikiMoteID",
        "org.contikios.cooja.mspmote.interfaces.MspMoteID",
    )

    # 3. Build target inside <commands>: only inside this tag.
    #    Also append a <firmware> tag with the path to the .sky binary,
    #    which SkyMoteType requires (the contikimote target inferred this
    #    automatically from <source>).
    def fix_commands(m):
        body = m.group(1)
        body = body.replace(".cooja", ".sky")
        body = body.replace("TARGET=cooja", "TARGET=sky")
        # Pull the firmware base name out of "make <name>.sky TARGET=sky"
        fw_match = re.search(r"(\S+)\.sky\b", body)
        fw_name = fw_match.group(1) if fw_match else "firmware"
        return (
            f"<commands>{body}</commands>\n"
            f"      <firmware EXPORT=\"discard\">[CONFIG_DIR]/build/sky/{fw_name}.sky</firmware>"
        )

    text = re.sub(
        r"<commands>(.*?)</commands>",
        fix_commands,
        text,
        flags=re.DOTALL,
    )

    # 4. Inside each <motetype>...</motetype>: drop existing <moteinterface>
    # lines, then re-insert the full Sky list right after <commands>.
    sky_block = "\n".join(
        f"      <moteinterface>{i}</moteinterface>" for i in SKY_INTERFACES
    )

    def rewrite_motetype(m):
        body = m.group(0)
        body = re.sub(
            r"[ \t]*<moteinterface>[^<]+</moteinterface>\n",
            "",
            body,
        )
        body = re.sub(
            r"(<commands>[^<]*</commands>\n)",
            r"\1" + sky_block + "\n",
            body,
            count=1,
        )
        return body

    text = re.sub(
        r"<motetype>.*?</motetype>",
        rewrite_motetype,
        text,
        flags=re.DOTALL,
    )

    # 5. Mark the title as a Sky variant
    text = re.sub(
        r"<title>([^<]+)</title>",
        lambda m: f"<title>{m.group(1)}_sky</title>",
        text,
        count=1,
    )

    return text


def main():
    project_dir = Path(__file__).parent
    csc_files = sorted(p for p in project_dir.glob("mtd_*.csc") if "_sky" not in p.stem)
    if not csc_files:
        print("No source .csc files found.", file=sys.stderr)
        return 1

    for src in csc_files:
        dst = src.with_name(src.stem + "_sky.csc")
        text = src.read_text(encoding="utf-8")
        out = convert(text)
        dst.write_text(out, encoding="utf-8")
        print(f"  created: {dst.name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
