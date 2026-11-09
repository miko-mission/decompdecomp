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


# ---------------------------------------------------------------------------
# Task 3: basic-block decomposition
# ---------------------------------------------------------------------------

# All control-transfer mnemonics (MIPS). jal/jalr are calls (control returns),
# so they do NOT start a new block; they are listed for terminator identification.
BRANCH_MNEMONICS = frozenset({
    "b", "beq", "bne", "blez", "bgtz", "bltz", "bgez", "beqz", "bnez",
    "bc1t", "bc1f", "j", "jr", "jal", "jalr",
})
_FALLTHROUGH = frozenset({
    "b", "beq", "bne", "blez", "bgtz", "bltz", "bgez", "beqz", "bnez", "bc1t", "bc1f",
})
_JR_J = frozenset({"jr", "j"})


@dataclass
class Block:
    index: int
    start: int
    end: int
    label: Optional[str]
    terminator: str


def decompose(parsed: ParsedAsm, jump_tables: list[JumpTable]) -> list[Block]:
    """Split the function into basic blocks. Leaders: index 0, each resolvable
    branch target, the fall-through after a conditional/`b` branch, the insn after
    any jr/j, and each in-function jump-table case target."""
    n = len(parsed.insns)
    if n == 0:
        return []
    leaders: set[int] = {0}
    for insn in parsed.insns:
        mn = insn.mnemonic
        if mn not in BRANCH_MNEMONICS:
            continue
        last = insn.operands.split(",")[-1].strip()
        target = parsed.label_to_index.get(last)
        if target is not None and 0 <= target < n:
            leaders.add(target)
        if (mn in _FALLTHROUGH or mn in _JR_J) and insn.index + 1 < n:
            leaders.add(insn.index + 1)
    for jt in jump_tables:
        for c in jt.cases:
            if c.in_func and c.target_index is not None and 0 <= c.target_index < n:
                leaders.add(c.target_index)

    starts = sorted(leaders)
    index_to_label = {idx: lbl for lbl, idx in parsed.label_to_index.items()}
    blocks: list[Block] = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else n
        terminator = parsed.insns[end - 1].mnemonic if end - 1 >= start else ""
        blocks.append(Block(index=i, start=start, end=end,
                            label=index_to_label.get(start), terminator=terminator))
    return blocks
