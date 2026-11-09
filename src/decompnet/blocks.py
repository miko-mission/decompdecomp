"""Decomposition of a target function into basic blocks, jump-table resolution,
and attribution of a compile's diff rows back to those blocks.

All functions here are pure (no engine/DB deps): the asm string in, plain data out.
Markers consumed by `attribute` are the ones produced by `decompnet.scoring.diff`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Task 1: asm parsing primitive
# ---------------------------------------------------------------------------

# A target-asm instruction line looks like:
#   /* <offset> <addr> <bytes> */\t<mnemonic>\t<operands>
# (the same "/* offset addr bytes */" splat that scoring.compact_asm strips).
_INSN_RE = re.compile(r"/\*\s*([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+\S+\s*\*/\s*(.*)$")
_LABEL_RE = re.compile(r"^\s*([A-Za-z_.$][\w.$]*):\s*$")


@dataclass(frozen=True)
class Insn:
    index: int
    addr: int
    mnemonic: str
    operands: str


@dataclass
class ParsedAsm:
    insns: list[Insn]
    label_to_index: dict[str, int]
    addr_to_index: dict[int, int]


def parse_asm(asm: str) -> ParsedAsm:
    """Parse target asm into indexed instructions plus label/addr→index maps.

    A label line maps to the index of the NEXT instruction. `addr` is the full
    vram (the second hex field of the comment splat)."""
    insns: list[Insn] = []
    label_to_index: dict[str, int] = {}
    addr_to_index: dict[int, int] = {}
    for line in (asm or "").splitlines():
        lm = _LABEL_RE.match(line)
        if lm:
            label_to_index[lm.group(1)] = len(insns)
            continue
        m = _INSN_RE.search(line)
        if not m:
            continue
        addr = int(m.group(2), 16)
        rest = m.group(3).strip()
        parts = rest.split(None, 1)
        mnemonic = parts[0] if parts else ""
        operands = parts[1].strip() if len(parts) > 1 else ""
        idx = len(insns)
        insns.append(Insn(index=idx, addr=addr, mnemonic=mnemonic, operands=operands))
        addr_to_index[addr] = idx
    return ParsedAsm(insns=insns, label_to_index=label_to_index, addr_to_index=addr_to_index)
