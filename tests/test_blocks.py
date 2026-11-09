from decompnet.blocks import parse_asm

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
