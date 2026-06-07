#!/usr/bin/env python3
"""
Modern Python3 parser for Apple BOM (Bill of Materials) files (.bom)
Used in macOS pkg archives and installer receipts.

Features:
  - Reads and parses BOM headers, tables, vars, and tree structures
  - Type safe with ctypes structures
  - Supports diagnostic dump (`--dump`) with formatted output
  - Written for Python 3.11+, Endianness-aware

Usage:
    python3 bom_parser.py --file BomExample.bom --dump
"""

import struct
import logging
import argparse
from ctypes import (
    BigEndianStructure,
    c_char,
    c_uint8,
    c_uint16,
    c_uint32,
    sizeof,
    memmove,
    addressof,
)
from typing import BinaryIO, List, Optional

# ---------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s", level=logging.INFO
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------
# Structured BOM classes
# ---------------------------------------------------------------------
class BOMHeader(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("magic", c_char * 8),
        ("version", c_uint32),
        ("numberOfBlocks", c_uint32),
        ("indexOffset", c_uint32),
        ("indexLength", c_uint32),
        ("varsOffset", c_uint32),
        ("varsLength", c_uint32),
    ]


class BOMPointer(BigEndianStructure):
    _pack_ = 1
    _fields_ = [("address", c_uint32), ("length", c_uint32)]


class BOMBlockTable(BigEndianStructure):
    _pack_ = 1
    _fields_ = [("numberOfBlockTablePointers", c_uint32)]


class BOMFreeList(BigEndianStructure):
    _pack_ = 1
    _fields_ = [("numberOfFreeListPointers", c_uint32)]


class BOMVars(BigEndianStructure):
    _pack_ = 1
    _fields_ = [("count", c_uint32)]


class BOMVar(BigEndianStructure):
    _pack_ = 1
    _fields_ = [("index", c_uint32), ("length", c_uint8)]


class BOMInfo(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("version", c_uint32),
        ("numberOfPaths", c_uint32),
        ("numberOfInfoEntries", c_uint32),
    ]


class BOMInfoEntry(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("unknown0", c_uint32),
        ("unknown1", c_uint32),
        ("unknown2", c_uint32),
        ("unknown3", c_uint32),
    ]


class BOMTree(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("tree", c_char * 4),
        ("version", c_uint32),
        ("child", c_uint32),
        ("blockSize", c_uint32),
        ("pathCount", c_uint32),
        ("unknown3", c_uint8),
    ]


class BOMPaths(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("isLeaf", c_uint16),
        ("count", c_uint16),
        ("forward", c_uint32),
        ("backward", c_uint32),
    ]


class BOMPathIndices(BigEndianStructure):
    _pack_ = 1
    _fields_ = [("index0", c_uint32), ("index1", c_uint32)]


class BOMFile(BigEndianStructure):
    _pack_ = 1
    _fields_ = [("parent", c_uint32)]


# ---------------------------------------------------------------------
# Utility & parser functions
# ---------------------------------------------------------------------
def struct_read(f: BinaryIO, class_type, advance: bool = True):
    """Reads bytes from file and interprets them as a ctypes BigEndianStructure."""
    sz = sizeof(class_type)
    data = f.read(sz)
    if len(data) != sz:
        raise EOFError(f"Unexpected EOF while reading {class_type.__name__}")
    obj = class_type()
    memmove(addressof(obj), data, sz)
    if not advance:
        f.seek(-sz, 1)
    return obj


class BOMParser:
    """Encapsulated BOM parser with printable diagnostics."""

    def __init__(self, filename: str):
        self.filename = filename

    def open(self) -> BinaryIO:
        return open(self.filename, "rb")

    def read_header(self, f: BinaryIO) -> BOMHeader:
        header = struct_read(f, BOMHeader)
        if not header.magic.startswith(b"Bom"):
            raise ValueError("Invalid BOM magic header")
        log.debug("Header read successfully.")
        return header

    def read_block_table(self, f: BinaryIO, header: BOMHeader):
        f.seek(header.indexOffset)
        table = struct_read(f, BOMBlockTable)
        pointers = [struct_read(f, BOMPointer) for _ in range(table.numberOfBlockTablePointers)]
        table.pointers = pointers
        log.debug(f"Read {len(pointers)} block table pointers.")
        return table

    def read_free_list(self, f: BinaryIO, header: BOMHeader, table: BOMBlockTable):
        offset = header.indexOffset + sizeof(c_uint32) + (
            table.numberOfBlockTablePointers * sizeof(BOMPointer)
        )
        f.seek(offset)
        fl = struct_read(f, BOMFreeList)
        fl.pointers = [struct_read(f, BOMPointer) for _ in range(fl.numberOfFreeListPointers)]
        return fl

    def read_vars(self, f: BinaryIO, header: BOMHeader):
        f.seek(header.varsOffset)
        vars_struct = struct_read(f, BOMVars)
        vars_struct.vars = []
        for _ in range(vars_struct.count):
            v = struct_read(f, BOMVar)
            v.name = f.read(v.length).decode(errors="ignore")
            vars_struct.vars.append(v)
        return vars_struct

    # -----------------------------------------------------------------
    # Diagnostic dump
    # -----------------------------------------------------------------
    def dump(self):
        with self.open() as f:
            header = self.read_header(f)
            log.info("BOM Header:")
            log.info(f"  Magic: {header.magic.decode(errors='ignore')}")
            log.info(f"  Version: {header.version}")
            log.info(f"  NumberOfBlocks: {header.numberOfBlocks}")
            log.info(f"  IndexOffset: {header.indexOffset}")
            log.info(f"  VarsOffset: {header.varsOffset}")

            table = self.read_block_table(f, header)
            non_null = sum(1 for p in table.pointers if p.address)
            log.info(f"\nBlockTable: {len(table.pointers)} entries ({non_null} non-null)")

            fl = self.read_free_list(f, header, table)
            log.info(f"FreeList: {fl.numberOfFreeListPointers} pointers")

            vars_struct = self.read_vars(f, header)
            var_names = [v.name for v in vars_struct.vars]
            log.info(f"\nVars: {vars_struct.count} — {var_names}")

            for v in vars_struct.vars:
                log.info(f"\n  Var '{v.name}' -> index {v.index} (len={v.length})")

            log.info("\n✅ BOM file parsed successfully.")


# ---------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Inspect and dump Apple BOM files.")
    parser.add_argument("--file", "-f", required=True, help="Path to .bom file.")
    parser.add_argument("--dump", action="store_true", help="Print BOM structure info.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging.")
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    try:
        parser_obj = BOMParser(args.file)
        if args.dump:
            parser_obj.dump()
        else:
            log.info("Use --dump to print diagnostic info.")
    except Exception as e:
        log.exception(f"Failed to parse BOM file: {e}")


if __name__ == "__main__":
    main()
