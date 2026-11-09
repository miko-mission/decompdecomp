from decompnet.blocks import parse_asm, resolve_jump_tables, decompose, attribute, Block, JumpTable, JumpCase

SAMPLE = """\
func:
/* 0 100000 27bdfff0 */\taddiu\t$sp, $sp, -0x10
/* 4 100004 1000ffff */\tb\t.L100000
.L100000:
/* 8 100008 03e00008 */\tjr\t$ra
"""


def test_parse_indexes_and_labels():
    p = parse_asm(SAMPLE)
    assert [i.mnemonic for i in p.insns] == ["addiu", "b", "jr"]
    assert p.insns[1].operands == ".L100000"
    assert p.label_to_index[".L100000"] == 2          # label resolves to NEXT insn
    assert p.addr_to_index[0x100008] == 2             # full addr (2nd comment field) maps to its insn
    assert p.insns[0].addr == 0x100000


# --- Task 2: jump-table resolution ---

JT_ASM = """\
/* 0 14a000 2c410003 */\tsltiu\t$1, $2, 0x3
/* 4 14a004 10200004 */\tbeqz\t$1, .Lout
/* 8 14a008 3c030021 */\tlui\t$3, %hi(jtbl_00211000)
/* c 14a00c 24631000 */\taddiu\t$3, $3, %lo(jtbl_00211000)
/* 10 14a010 00621021 */\taddu\t$2, $2, $3
/* 14 14a014 00400008 */\tjr\t$2
/* 18 14a018 00000000 */\tnop
.Lout:
/* 1c 14a01c 03e00008 */\tjr\t$ra
"""


def _reader(words):  # words at 0x211000, little-endian u32
    blob = b"".join(w.to_bytes(4, "little") for w in words)
    return lambda addr, n: blob[addr - 0x211000: addr - 0x211000 + n] if 0x211000 <= addr < 0x211000 + len(blob) else None


def test_resolve_reads_N_entries_and_maps_targets():
    p = parse_asm(JT_ASM)
    r = _reader([0x14a018, 0x14a01c, 0x14a000, 0x99999999])  # 4 words present; bounds check says N=3
    [jt] = resolve_jump_tables(p, r, big_endian=False, func_lo=0x14a000, func_hi=0x14a020)
    assert jt.addr == 0x211000 and jt.symbol == "jtbl_00211000"
    assert [c.case for c in jt.cases] == [0, 1, 2]                 # only N=3 read, not the 4th
    assert jt.cases[0].target_addr == 0x14a018 and jt.cases[0].target_index == 6
    assert jt.cases[2].in_func is True


def test_reader_miss_skips_table():
    p = parse_asm(JT_ASM)
    assert resolve_jump_tables(p, (lambda a, n: None), False, 0x14a000, 0x14a020) == []


def test_no_jumptable_returns_empty():
    p = parse_asm("/* 0 14a000 03e00008 */\tjr\t$ra\n")
    assert resolve_jump_tables(p, (lambda a, n: b"\0\0\0\0"), False, 0x14a000, 0x14a004) == []


# --- Task 3: basic-block decomposition ---

def test_single_block_when_no_branches():
    p = parse_asm("/* 0 14a000 27bdfff0 */\taddiu\t$sp,$sp,-0x10\n/* 4 14a004 03e00008 */\tjr\t$ra\n")
    b = decompose(p, [])
    assert len(b) == 1 and b[0].start == 0 and b[0].end == 2


def test_branch_target_and_fallthrough_make_blocks():
    p = parse_asm("""\
/* 0 14a000 1000ffff */\tb\t.LT
/* 4 14a004 00000000 */\tnop
.LT:
/* 8 14a008 03e00008 */\tjr\t$ra
""")
    blocks = decompose(p, [])
    assert [(b.start, b.end) for b in blocks] == [(0, 1), (1, 2), (2, 3)]
    assert blocks[0].terminator == "b"


def test_jumptable_targets_are_leaders():
    p = parse_asm("/* 0 14a000 1 */\tnop\n/* 4 14a004 2 */\tnop\n/* 8 14a008 3 */\tnop\n")
    jt = JumpTable(addr=0x211000, symbol="jtbl_00211000", cases=[JumpCase(0, 0x14a008, 2, True)])
    assert any(b.start == 2 for b in decompose(p, [jt]))


# --- Task 4: per-block diff attribution ---

def _blocks3():
    return [Block(0, 0, 2, None, "nop"), Block(1, 2, 4, None, "nop"), Block(2, 4, 6, None, "nop")]


def test_clean_bytepending_diffing():
    rows = [(" ", "a", "a"), (" ", "b", "b"),    # block0: all equal -> clean
            ("r", "c", "c"), ("o", "d", "d"),    # block1: regalloc+reorder -> byte_pending
            ("|", "e", "x"), (" ", "f", "f")]    # block2: a different insn -> diffing
    st = {s.block_index: s.status for s in attribute(_blocks3(), rows)}
    assert st == {0: "clean", 1: "byte_pending", 2: "diffing"}


def test_extra_rows_do_not_advance_target_and_flag_low_confidence():
    rows = [(">", "", "x"), (">", "", "y"), (">", "", "z"), (" ", "a", "a")]  # 3 extras in block0
    st = attribute(_blocks3(), rows)
    assert st[0].status == "low_confidence"


def test_reorder_rewritten_insertion_does_not_desync():
    # scoring.diff's reorder pass rewrites an inserted (candidate-only) row to marker "o"
    # with an EMPTY target. It must be treated as candidate-only (no cursor advance), or it
    # desyncs attribution of every later row and mislabels block0 as byte_pending.
    rows = [(" ", "a", "a"), ("o", "", "x"), (" ", "b", "b"),  # block0 [0,2): equal, inserted-o, equal
            (" ", "c", "c"), (" ", "d", "d"),                   # block1 [2,4): equal, equal
            (" ", "e", "e"), (" ", "f", "f")]                   # block2 [4,6): equal, equal
    st = {s.block_index: s.status for s in attribute(_blocks3(), rows)}
    assert st == {0: "clean", 1: "clean", 2: "clean"}
