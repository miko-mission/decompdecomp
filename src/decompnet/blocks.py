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


# ---------------------------------------------------------------------------
# Task 2: jump-table resolution
# ---------------------------------------------------------------------------

_JTBL_RE = re.compile(r"jtbl_([0-9A-Fa-f]+)")


@dataclass
class JumpCase:
    case: int
    target_addr: int
    target_index: Optional[int]
    in_func: bool


@dataclass
class JumpTable:
    addr: int
    symbol: str
    cases: list[JumpCase]


def _case_count_before(parsed: ParsedAsm, ref_index: int) -> Optional[int]:
    """The N from the nearest `sltiu _, _, <imm>` bounds check at or before ref_index."""
    for j in range(ref_index, -1, -1):
        insn = parsed.insns[j]
        if insn.mnemonic == "sltiu":
            last = insn.operands.split(",")[-1].strip()
            try:
                return int(last, 0)
            except ValueError:
                return None
    return None


def resolve_jump_tables(
    parsed: ParsedAsm,
    reader: Callable[[int, int], Optional[bytes]],
    big_endian: bool,
    func_lo: int,
    func_hi: int,
) -> list[JumpTable]:
    """Resolve each `jtbl_<hex>` referenced in the asm by reading its rodata words
    (bounded by the dispatch's sltiu case count) through `reader(addr, n)`."""
    byteorder = "big" if big_endian else "little"
    refs: dict[str, tuple[int, int]] = {}  # symbol -> (table_addr, first_ref_insn_index)
    for insn in parsed.insns:
        for m in _JTBL_RE.finditer(insn.operands):
            sym = "jtbl_" + m.group(1)
            if sym not in refs:
                refs[sym] = (int(m.group(1), 16), insn.index)

    tables: list[JumpTable] = []
    for sym, (addr, ref_index) in refs.items():
        n = _case_count_before(parsed, ref_index)
        if not n or n <= 0:
            continue
        cases: list[JumpCase] = []
        ok = True
        for k in range(n):
            b = reader(addr + 4 * k, 4)
            if b is None or len(b) < 4:
                ok = False
                break
            target = int.from_bytes(b[:4], byteorder)
            cases.append(
                JumpCase(
                    case=k,
                    target_addr=target,
                    target_index=parsed.addr_to_index.get(target),
                    in_func=func_lo <= target < func_hi,
                )
            )
        if ok:
            tables.append(JumpTable(addr=addr, symbol=sym, cases=cases))
    return tables
