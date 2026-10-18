from __future__ import annotations

import os
import re
from typing import Any, TypedDict, cast

from bson import json_util


class HeroUser(TypedDict, total=False):
    email: str


class ActivityRecord(TypedDict, total=False):
    createdAt: str
    resourceName: str
    tesupportUser: str
    heroUser: HeroUser


def transform_mongo_shell_to_extended_json(text: str) -> str:
    """
    Convert Mongo shell style (ISODate/Long, unquoted keys, single quotes) to Extended JSON.
    """

    # Normalize curly apostrophes to straight apostrophes
    text = text.replace("\u2019", "'").replace("\u2018", "'")

    # Remove non-printable control characters except tab/newline/carriage return
    text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", text)

    i = 0
    length = len(text)
    out_chars: list[str] = []

    def startswith_at(prefix: str) -> bool:
        return text.startswith(prefix, i)

    def read_single_quoted() -> str:
        """Convert a single-quoted string into a JSON-safe double-quoted string."""
        nonlocal i
        i += 1  # skip opening '
        buf: list[str] = []
        escape = False
        while i < length:
            ch = text[i]
            if escape:
                buf.append(ch)
                escape = False
                i += 1
                continue
            if ch == "\\":
                buf.append("\\")
                escape = True
                i += 1
                continue
            if ch == "'":
                i += 1  # consume closing '
                break
            buf.append(ch)
            i += 1
        # Escape for JSON
        content = "".join(buf).replace("\\", r"\\").replace('"', r"\"")
        return f'"{content}"'

    def read_identifier_key() -> str | None:
        """Quote unquoted object keys like foo: -> "foo":"""
        nonlocal i
        j = i
        if j < length and (text[j].isalpha() or text[j] == "_"):
            j += 1
            while j < length and (text[j].isalnum() or text[j] == "_"):
                j += 1
            k = j
            while k < length and text[k].isspace():
                k += 1
            if k < length and text[k] == ":":
                key = text[i:j]
                i = k + 1  # consume up to and including ':'
                return f'"{key}":'
        return None

    def read_wrapped_function(name: str, wrapper_key: str) -> str | None:
        """Handle wrappers like ISODate('...') -> {"$date":"..."}"""
        nonlocal i
        if startswith_at(name + "("):
            i += len(name) + 1
            while i < length and text[i].isspace():
                i += 1
            if i < length and text[i] in ("'", '"'):
                quote = text[i]
                i += 1
                buf: list[str] = []
                escape = False
                while i < length:
                    ch = text[i]
                    if escape:
                        buf.append(ch)
                        escape = False
                        i += 1
                        continue
                    if ch == "\\":
                        buf.append("\\")
                        escape = True
                        i += 1
                        continue
                    if ch == quote:
                        i += 1
                        break
                    buf.append(ch)
                    i += 1
                # skip spaces and closing paren
                while i < length and text[i].isspace():
                    i += 1
                if i < length and text[i] == ")":
                    i += 1
                value = "".join(buf).replace("\\", r"\\").replace('"', r"\"")
                return f'{{"{wrapper_key}":"{value}"}}'
        return None

    in_double = False
    escape_next = False
    while i < length:
        ch = text[i]
        if in_double:
            out_chars.append(ch)
            i += 1
            if escape_next:
                escape_next = False
            elif ch == "\\":
                escape_next = True
            elif ch == '"':
                in_double = False
            continue

        if ch == '"':
            in_double = True
            out_chars.append(ch)
            i += 1
            continue

        for name, key in (
            ("ISODate", "$date"),
            ("NumberLong", "$numberLong"),
            ("Long", "$numberLong"),
            ("ObjectId", "$oid"),
        ):
            wrapped = read_wrapped_function(name, key)
            if wrapped is not None:
                out_chars.append(wrapped)
                break
        else:
            prev = out_chars[-1] if out_chars else ""
            if prev in ("{", ",", "\n", "\r", "\t", " "):
                key_token = read_identifier_key()
                if key_token is not None:
                    out_chars.append(key_token)
                    continue

            if ch == "'":
                out_chars.append(read_single_quoted())
                continue

            out_chars.append(ch)
            i += 1

    text = "".join(out_chars)

    # Remove trailing commas before } or ]
    text = re.sub(r",\s*(\})", r"\1", text)
    text = re.sub(r",\s*(\])", r"\1", text)

    # Ensure top-level is a JSON array
    stripped = text.strip()
    while stripped.endswith("]") and not stripped.startswith("["):
        stripped = stripped[:-1].rstrip()
    if not stripped.startswith("["):
        stripped = f"[\n{re.sub(r',\s*$', '', stripped)}\n]"

    return stripped


def load_user_activity(input_file: str) -> list[ActivityRecord] | dict[str, Any]:
    """Load and parse user activity from a text file into typed records."""
    with open(input_file, "r", encoding="utf-8") as f:
        raw_text = f.read()

    transformed = transform_mongo_shell_to_extended_json(raw_text)

    try:
        return cast(list[ActivityRecord] | dict[str, Any], json_util.loads(transformed))
    except Exception as e:
        out_path = os.path.join(os.path.dirname(input_file), "user_activity_transformed.json")
        with open(out_path, "w", encoding="utf-8") as out:
            out.write(transformed)
        raise RuntimeError(
            f"Failed to parse transformed JSON, wrote debug file to {out_path}"
        ) from e


def main() -> None:
    input_path = os.path.join(os.path.dirname(__file__), "user_activity.txt")
    data = load_user_activity(input_path)

    if isinstance(data, list):
        print(f"Parsed {len(data)} records")
        if data and isinstance(data[0], dict):
            sample_keys = sorted(data[0].keys())
            print(f"Sample top-level keys: {sample_keys[:12]}")
        for record in data:
            created = record.get("createdAt")
            name = record.get("resourceName")
            user = record.get("tesupportUser")
            hero_email = record.get("heroUser", {}).get("email") if "heroUser" in record else None
            print(f"{created} - {name} - {user} - {hero_email}")
    elif isinstance(data, dict):
        print(f"Parsed top-level object with {len(data)} keys")
        sample_keys = sorted(data.keys())
        print(f"Sample top-level keys: {sample_keys[:12]}")
    else:
        print(f"Parsed object of type: {type(data)}")


if __name__ == "__main__":
    main()
