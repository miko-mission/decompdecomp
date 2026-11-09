"""The local engine on Demo Quest 64: import, claim, split, match, rename, read data, export."""

import shutil
from pathlib import Path

import pytest

from decompnet import toolchains
from decompnet.app.engine import RomNetwork
from decompnet.network import NetworkError

from .test_rom import built  # noqa: F401  (fixture that builds the demo ROM)

pytestmark = pytest.mark.skipif(toolchains.installed("gcc-2.7.2-kmc") is None or not shutil.which("ld.lld"),
                                reason="needs gcc-2.7.2-kmc and ld.lld to build the demo ROM")

CLAMP = """s32 func_800007D0(s32 v, s32 lo, s32 hi) {
    if (v < lo) {
        return lo;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}"""

DAMAGE = """typedef struct {
    u8 ent[0x1C];
    s32 hp;
    s16 invuln_timer;
    s16 state;
    s32 combo;
} Player;
extern Player D_8004AE34;

void func_80000808(s32 amount) {
    if (D_8004AE34.invuln_timer > 0) {
        return;
    }
    D_8004AE34.hp -= amount;
    if (D_8004AE34.hp <= 0) {
        D_8004AE34.hp = 0;
        D_8004AE34.state = 3;
    }
    D_8004AE34.invuln_timer = 60;
}"""


@pytest.fixture(scope="module")
def net(built, tmp_path_factory):  # noqa: F811
    ws = tmp_path_factory.mktemp("ws")
    net = RomNetwork(ws / "decomp.db", ws)
    slug = net.import_rom(built, confirmed=True, log=lambda *_: None)
    assert slug == "demo-quest-64"
    return net


def test_import_needs_the_ownership_confirmation(built, tmp_path):  # noqa: F811
    with pytest.raises(NetworkError, match="legally obtained"):
        RomNetwork(tmp_path / "d.db", tmp_path).import_rom(built, log=lambda *_: None)


def test_import_is_idempotent_and_described(net, built):  # noqa: F811
    assert net.import_rom(built, confirmed=True, log=lambda *_: None) == "demo-quest-64"
    ov = net.overview("demo-quest-64")
    assert ov["functions"] >= 95 and ov["matched"] == 0 and ov["compiler"]["toolchain"] == "gcc-2.7.2-kmc"
    assert ov["rom"]["game_code"] == "NDQE"


def test_split_match_and_rename(net):
    agent, _ = net.local_agent("tester")
    # exit() never returns, so the disassembler ran it into clamp_s32: split them, then match clamp_s32
    assert "split" in net.split_function(agent, "demo-quest-64", "func_800007C4", "0x800007D0")
    brief = net.claim(agent, "demo-quest-64", "func_800007D0")
    assert "0x800007D0" in brief and "slt " in brief and "m2c" in brief
    out = net.compile_and_diff(agent, "func_800007D0", CLAMP, "demo-quest-64")
    assert out.startswith("✅ MATCH"), out
    out = net.rename_symbol(agent, "demo-quest-64", "func_800007D0", "clamp_s32")
    assert out.startswith("✅"), out
    assert net._function("clamp_s32", "demo-quest-64")["status"] == "matched"
    assert "clamp_s32" in net._function("clamp_s32", "demo-quest-64")["matched_source"]


def test_struct_access_through_an_automatic_name(net):
    agent, _ = net.local_agent("tester2")
    brief = net.get_function("func_80000808", "demo-quest-64")
    assert "D_8004AE50" in brief  # g_player.hp, as the assembly names it
    out = net.compile_and_diff(agent, "func_80000808", DAMAGE, "demo-quest-64")
    assert out.startswith("✅ MATCH"), out
    # renaming the struct's address keeps the match (the source is updated with it)
    assert net.rename_symbol(agent, "demo-quest-64", "D_8004AE34", "g_player").startswith("✅")
    assert "g_player.hp" in net._function("func_80000808", "demo-quest-64")["matched_source"]


def test_wrong_code_gets_a_diff_and_link_notes(net):
    agent, _ = net.local_agent("tester3")
    out = net.compile_and_diff(agent, "func_80000A0C", "void func_80000A0C(s32 p) { mystery(p); }", "demo-quest-64")
    assert "score" in out and "mystery" in out
    # the GUI's diff: the same judge, row by row, with the link problems
    d = net.function_diff("demo-quest-64", "func_80000A0C")
    assert d["kind"] == "latest" and d["score"] > 0 and any(r[0] != " " for r in d["rows"])
    assert any("mystery" in p for p in d["problems"])
    assert net.function_diff("demo-quest-64", "func_80000A0C") == d  # cached
    net.compile_and_diff(agent, "func_80000A0C", "void func_80000A0C(s32 p) { p = }", "demo-quest-64")
    broken = net.function_diff("demo-quest-64", "func_80000A0C")
    assert broken["rows"] is None and broken["error"]
    assert net.function_diff("demo-quest-64", "func_80000A0C", "best")["score"] == d["score"]
    assert net.function_diff("demo-quest-64", "func_80000B3C")["rows"] is None  # nothing tried yet
    net.release(agent, "func_80000A0C", "not this", "demo-quest-64")


def test_read_data_and_lists(net):
    text = net.read_data("demo-quest-64", "0x800082C0", 16)
    assert "DEMOQUEST-SAVE" in text
    assert "bss" in net.read_data("demo-quest-64", "g_player", 16)
    assert "clamp_s32" in net.list_functions("demo-quest-64", "matched")


def test_export_and_live(net):
    out = net.export_rom("demo-quest-64", log=lambda *_: None)
    assert out["identical"], out["log"]
    assert "clamp_s32" in (Path(out["path"]) / "src" / "main" / "clamp_s32.c").read_text()
    live = net.live("demo-quest-64")
    assert live["overview"]["matched"] >= 2 and any(e["kind"] == "match" for e in live["events"])
    fmap = net.function_map("demo-quest-64")
    assert sum(f["status"] == "matched" for f in fmap) >= 2
    detail = net.function_detail("demo-quest-64", "clamp_s32")
    assert detail["status"] == "matched" and detail["scores"]
    d = net.function_diff("demo-quest-64", "clamp_s32")
    assert d["kind"] == "matched" and d["score"] == 0 and all(r[0] == " " for r in d["rows"])
    assert any(f["matched_at"] for f in fmap) and all("unit" in f for f in fmap)
    assert net.overview("demo-quest-64")["last_activity"]


def test_find_similar_on_the_rom(net):
    import time

    t = time.time()
    names = [r["name"] for r in net.store.all("SELECT name FROM functions WHERE n_insns > 12 LIMIT 40")]
    outs = [net.find_similar("demo-quest-64", n) for n in names]
    assert time.time() - t < 20
    assert all(o.startswith(("Functions that look like", "No look-alikes")) for o in outs)


def test_autopilot_matches_machine_drafts_for_free(net):
    import time

    before = net.overview("demo-quest-64")["matched"]
    net.start_autopilot("demo-quest-64")
    for _ in range(600):
        if net.autopilot_status("demo-quest-64")["state"] != "running":
            break
        time.sleep(0.1)
    st = net.autopilot_status("demo-quest-64")
    assert st["state"] == "done" and st["tried"] == st["total"] and st["matched"] > 0
    ov = net.overview("demo-quest-64")
    assert ov["matched"] == before + st["matched"] and ov["autopilot"]["matched"] == st["matched"]
    by = net.store.one("SELECT COUNT(*) AS n FROM functions f JOIN agents a ON a.id=f.matched_agent_id "
                       "WHERE a.name='autopilot'")["n"]
    assert by == st["matched"]
    assert not net.store.one("SELECT 1 FROM claims c JOIN agents a ON a.id=c.agent_id WHERE a.name='autopilot'")


def test_steering_priority_instructions_spend(net):
    slug = "demo-quest-64"
    open_fn = net.store.one("SELECT name FROM functions WHERE status='open' ORDER BY n_insns DESC LIMIT 1")["name"]
    assert net.set_priority(slug, open_fn) == [open_fn]
    agent, _ = net.local_agent("steered")
    assert open_fn in net.claim(agent, slug)  # the user's pick comes first, whatever the strategy
    net.release(agent, open_fn, "testing priorities", slug)
    net.set_priority(slug, open_fn, on=False)
    net.set_instructions(slug, "Focus on the game's own code first.")
    from decompnet.app import tools
    assert "Focus on the game's own code first." in tools.project_info(net, slug)
    net.add_spend(slug, 0.25, 0)
    net.add_spend(slug, 0.5, 1200)
    sp = net.overview(slug)["spend"]
    assert round(sp["usd"], 2) == 0.75 and sp["tokens"] == 1200


def test_stats_say_who_matched_what_and_how_fast(net):
    st = net.stats("demo-quest-64")
    assert len(st["matches_per_hour"]) == 24
    agent, _ = net.local_agent("statsy")
    net.compile_and_diff(agent, "func_80000A0C", "void func_80000A0C(s32 p) { }", "demo-quest-64")
    st = net.stats("demo-quest-64")
    me = next(r for r in st["agents"] if r["agent"] == "statsy")
    assert me["compiles"] == 1 and st["compiles_last_hour"] >= 1
    assert all("matched_by" in r for r in net.function_map("demo-quest-64"))


def test_a_project_can_be_renamed(net):
    """A disc's title is often only its serial (GTA San Andreas imports as SLES-52541): the user names it. The slug
    stays, so links, folders and history keep working."""
    slug = net.store.one("SELECT slug FROM projects LIMIT 1")["slug"]
    assert net.set_title(slug, "  Demo   Quest  ") == "Demo Quest"
    assert net.overview(slug)["title"] == "Demo Quest" and net.overview(slug)["slug"] == slug
    for bad in ("   ", "x" * 81):
        with pytest.raises(NetworkError):
            net.set_title(slug, bad)


def test_boundary_reports_wait_for_the_user(net):
    """A function that runs on into padding or linker leftovers can never match whole. An agent reports where it
    really ends; nothing changes until the user approves, then it ends there and the rest is set aside."""
    slug = "demo-quest-64"
    pid = net.project_row(slug)["id"]
    agent, _ = net.local_agent("boundary-agent")
    fns = net.store.all("SELECT * FROM functions WHERE project_id=? AND status='open' AND size>=16 ORDER BY vram LIMIT 2", pid)
    fn, other = fns[0], fns[1]
    end = fn["vram"] + fn["size"] - 8
    with pytest.raises(NetworkError, match="isn't a word inside"):
        net.request_boundary(agent, slug, fn["name"], f"0x{fn['vram'] + fn['size'] + 4:X}", "padding")
    with pytest.raises(NetworkError, match="say what the bytes"):
        net.request_boundary(agent, slug, fn["name"], f"0x{end:X}", "   ")
    assert net.request_boundary(agent, slug, fn["name"], f"0x{end:X}", "two words of alignment padding").startswith("Reported")
    [req] = [r for r in net.overview(slug)["boundaries"] if r["function"] == fn["name"]]
    assert req["cut"] == 8 and len(req["rest"].split()) == 2
    assert net.store.one("SELECT size FROM functions WHERE id=?", fn["id"])["size"] == fn["size"]  # not before approval
    net.resolve_boundary(slug, req["id"], apply=True)
    assert net.store.one("SELECT size FROM functions WHERE id=?", fn["id"])["size"] == fn["size"] - 8
    pad = net.store.one("SELECT * FROM functions WHERE project_id=? AND name=?", pid, f"pad_{end:08X}")
    assert pad["status"] == "asm" and pad["size"] == 8 and "alignment padding" in pad["meta"]
    assert not [r for r in net.overview(slug)["boundaries"] if r["function"] == fn["name"]]
    if toolchains.installed("binutils-mips") is not None:  # the set-aside bytes are still built, as assembly
        out = net.export_rom(slug, log=lambda *_: None)
        assert out["identical"], out.get("log")
    # dismissed: nothing changes
    net.request_boundary(agent, slug, other["name"], f"0x{other['vram'] + 4:X}", "data, not code")
    [req] = [r for r in net.overview(slug)["boundaries"] if r["function"] == other["name"]]
    net.resolve_boundary(slug, req["id"], apply=False)
    assert net.store.one("SELECT size FROM functions WHERE id=?", other["id"])["size"] == other["size"]


def test_overview_vote_model_warning(net):  # noqa: F811
    import time as _t
    slug = "demo-quest-64"
    pid = net._project(slug)["id"]
    with net.store.tx() as db:  # age out earlier tests' activity so the vote-model window starts clean (last test)
        db.execute("UPDATE events SET created_at = created_at - 1000000 WHERE project_id=?", (pid,))

    def active(name):
        ag, _ = net.local_agent(name)
        with net.store.tx() as db:
            db.execute("INSERT INTO events(project_id, agent_id, kind, detail, created_at) VALUES(?,?,'claim','f',?)",
                       (pid, ag.id, _t.time()))

    active("codex-gpt-6-luna-1")                       # one model running
    vm = net.overview(slug)["vote_models"]
    assert vm["required"] == 2 and "codex-gpt-6-luna" in vm["present"] and vm["enough"] is False
    active("claude-haiku-5-5-1")                        # a second, distinct model
    vm = net.overview(slug)["vote_models"]
    assert vm["enough"] is True and {"codex-gpt-6-luna", "claude-haiku-5-5"} <= set(vm["present"])


def test_subtract_ranges():
    from decompnet.app.engine.compilers import CompilerMixin as _C  # staticmethod, no instance needed
    sub = _C._subtract_ranges
    assert sub([(0, 100)], [(40, 60)]) == [[0, 40], [60, 100]]        # hole in the middle -> two pieces
    assert sub([(0, 100)], [(0, 100)]) == []                          # whole range removed
    assert sub([(0, 100)], [(90, 200)]) == [[0, 90]]                  # hole past the end, clipped
    assert sub([(0, 100)], [(10, 20), (30, 40)]) == [[0, 10], [20, 30], [40, 100]]  # two holes
    assert sub([(0, 50), (100, 150)], [(10, 20)]) == [[0, 10], [20, 50], [100, 150]]


def test_set_compiler_ranges_auto_narrows_around_matched(net, monkeypatch):  # noqa: F811
    slug = "demo-quest-64"
    pid = net._project(slug)["id"]
    with net.store.tx() as db:  # the first function is a matched breaker; the second rides along as a survivor
        ids = [r[0] for r in db.execute("SELECT id FROM functions WHERE project_id=? AND size>0 ORDER BY vram LIMIT 2", (pid,)).fetchall()]
        db.execute("UPDATE functions SET status='matched', matched_source='/* m */' WHERE id=?", (ids[0],))
    m = net.store.one("SELECT name, vram, size FROM functions WHERE id=?", ids[0])
    nxt = net.store.one("SELECT name, vram, size FROM functions WHERE id=?", ids[1])
    a, b = m["vram"], nxt["vram"] + (nxt["size"] or 1)      # covers the breaker and the survivor after it
    # the matched function "breaks" only while it is still inside the tested range; the survivor never breaks
    monkeypatch.setattr(net, "regression_test",
                        lambda proj, x, only=None, **k: [(m["name"], None)] if any(f["name"] == m["name"] for f in (only or [])) else [])
    import types as _t
    monkeypatch.setattr(net, "_judge_with", lambda *a, **k: (None, _t.SimpleNamespace(score=0), []))  # no open regresses
    tc = net.overview(slug)["compiler"]["toolchain"]
    net.set_compiler_ranges(slug, [[a, b]], tc, flags=["-O2"])
    ranges = net.cfg(net._project(slug))["compiler_ranges"]
    assert not any(r["start"] <= m["vram"] < r["end"] for r in ranges), "breaker still covered"       # carved out
    assert any(r["start"] <= nxt["vram"] < r["end"] for r in ranges), "survivor lost the compiler"    # survivor kept


def test_set_compiler_ranges_auto_narrows_around_open_near_miss(net, monkeypatch):  # noqa: F811
    import types
    slug = "demo-quest-64"
    pid = net._project(slug)["id"]
    with net.store.tx() as db:  # an OPEN near-miss breaker, with a survivor function riding along in the range
        ids = [r[0] for r in db.execute("SELECT id FROM functions WHERE project_id=? AND size>0 ORDER BY vram LIMIT 2", (pid,)).fetchall()]
        db.execute("UPDATE functions SET status='open', best_source='/* near */', best_score=50, n_insns=100 WHERE id=?", (ids[0],))
    fn = net.store.one("SELECT name, vram, size FROM functions WHERE id=?", ids[0])
    nxt = net.store.one("SELECT name, vram, size FROM functions WHERE id=?", ids[1])
    a, b = fn["vram"], nxt["vram"] + (nxt["size"] or 1)   # covers the near-miss breaker and the survivor
    monkeypatch.setattr(net, "regression_test", lambda *a, **k: [])        # no matched breakers
    # the near-miss scores worse under the candidate compiler (50 -> 9999); every other function is fine
    monkeypatch.setattr(net, "_judge_with",
                        lambda proj, f, tc, fl, src: (None, types.SimpleNamespace(score=9999 if f["name"] == fn["name"] else 0), []))
    tc = net.overview(slug)["compiler"]["toolchain"]
    net.set_compiler_ranges(slug, [[a, b]], tc, flags=["-O2"])
    ranges = net.cfg(net._project(slug))["compiler_ranges"]
    assert not any(r["start"] <= fn["vram"] < r["end"] for r in ranges), "near-miss still covered"     # carved out
    assert any(r["start"] <= nxt["vram"] < r["end"] for r in ranges), "survivor lost the compiler"     # survivor kept


def test_recheck_compiler_ranges_unsticks_mis_assigned(net, monkeypatch):  # noqa: F811
    """A sweep over existing ranges: a range holding an open near-miss that scores worse under its own compiler is
    narrowed around it; a range whose near-miss is fine is left untouched. The count is real narrows, not ranges
    looked at."""
    import types
    slug = "demo-quest-64"
    pid = net._project(slug)["id"]
    fns = net.store.all("SELECT id, name, vram, size FROM functions WHERE project_id=? AND size>0 ORDER BY vram LIMIT 4", pid)
    assert len(fns) == 4
    badfn, keepA, okfn, keepB = fns     # badfn regresses (gets carved); okfn is fine (its range is left alone)
    with net.store.tx() as db:
        for fn in (badfn, okfn):        # both are open near-misses by the pre-filter
            db.execute("UPDATE functions SET status='open', best_source='/* near */', best_score=50, n_insns=100 WHERE id=?", (fn["id"],))
    tc = net.overview(slug)["compiler"]["toolchain"]
    rA = {"start": badfn["vram"], "end": keepA["vram"] + (keepA["size"] or 1), "toolchain": tc, "flags": ["-O2"]}
    rB = {"start": okfn["vram"], "end": keepB["vram"] + (keepB["size"] or 1), "toolchain": tc, "flags": ["-O2"]}
    net._update_cfg(slug, lambda cfg: cfg.__setitem__("compiler_ranges", [rA, rB]))
    monkeypatch.setattr(net, "regression_test", lambda *a, **k: [])          # no matched breakers
    # only badfn scores worse under its range's compiler; everything else (okfn, the survivors) is fine
    monkeypatch.setattr(net, "_judge_with",
                        lambda proj, fn, t, fl, src: (None, types.SimpleNamespace(score=9999 if fn["name"] == badfn["name"] else 0), []))
    narrowed = net.recheck_compiler_ranges(slug)
    assert narrowed == 1, f"expected exactly one range narrowed, got {narrowed}"
    ranges = net.cfg(net._project(slug))["compiler_ranges"]
    assert not any(r["start"] <= badfn["vram"] < r["end"] for r in ranges), "mis-assigned near-miss still covered"
    assert any(r["start"] <= okfn["vram"] < r["end"] for r in ranges), "the fine range was disturbed"


def test_set_compiler_ranges_records_a_narrow_event(net, monkeypatch):  # noqa: F811
    """Every auto-narrow leaves a 'narrow' event naming the carved functions, so the carve shows in the live feed
    whatever triggered it (object-compiler pass, an agent's suggestion, or the re-check sweep)."""
    import types
    slug = "demo-quest-64"
    pid = net._project(slug)["id"]
    with net.store.tx() as db:
        ids = [r[0] for r in db.execute("SELECT id FROM functions WHERE project_id=? AND size>0 ORDER BY vram LIMIT 2", (pid,)).fetchall()]
        db.execute("UPDATE functions SET status='matched', matched_source='/* m */' WHERE id=?", (ids[0],))
    m = net.store.one("SELECT name, vram, size FROM functions WHERE id=?", ids[0])
    nxt = net.store.one("SELECT name, vram, size FROM functions WHERE id=?", ids[1])
    a, b = m["vram"], nxt["vram"] + (nxt["size"] or 1)
    monkeypatch.setattr(net, "regression_test",
                        lambda proj, x, only=None, **k: [(m["name"], None)] if any(f["name"] == m["name"] for f in (only or [])) else [])
    monkeypatch.setattr(net, "_judge_with", lambda *a, **k: (None, types.SimpleNamespace(score=0), []))
    before = net.store.one("SELECT COALESCE(MAX(id), 0) AS id FROM events WHERE project_id=?", pid)["id"]
    tc = net.overview(slug)["compiler"]["toolchain"]
    net.set_compiler_ranges(slug, [[a, b]], tc, flags=["-O2"])
    ev = net.store.all("SELECT detail FROM events WHERE project_id=? AND id>? AND kind='narrow'", pid, before)
    assert ev, "no narrow event recorded"
    assert m["name"] in ev[0]["detail"], "carved function not named in the narrow event"


# --- Chunked decomposition Increment 1: read-only Blocks section ---

def test_brief_has_blocks_section(net):
    agent, _ = net.local_agent("blocks_tester")
    # a candidate that compiles/links but does not match -> a non-clean diff
    net.compile_and_diff(agent, "func_80000A0C", "void func_80000A0C(s32 p) { mystery(p); }", "demo-quest-64")
    brief = net.get_function("func_80000A0C", "demo-quest-64", agent)
    assert "### Blocks" in brief
    assert "block 0" in brief
    assert any(tok in brief for tok in ("diffing", "byte_pending", "low_confidence"))


def test_blocks_section_absent_without_asm(net):
    proj = net.store.one("SELECT * FROM projects WHERE slug=?", "demo-quest-64")
    assert net._blocks_brief({"asm": "", "vram": 0, "size": 0, "id": -1}, proj, None) == []


def test_blocks_brief_resolves_jumptables_from_raw_asm_not_renamed():
    # rename_tokens rewrites jtbl_XXXXXXXX -> D_XXXXXXXX (unnamed jump-table addresses).
    # _blocks_brief must resolve jump tables from the RAW asm (jtbl_ intact), not the renamed one.
    from decompnet.app.engine import RomNetwork
    JT = ("/* 0 14a000 2c410001 */\tsltiu\t$1, $2, 0x1\n"
          "/* 4 14a004 3c030021 */\tlui\t$3, %hi(jtbl_00211000)\n"
          "/* 8 14a008 24631000 */\taddiu\t$3, $3, %lo(jtbl_00211000)\n"
          "/* c 14a00c 00400008 */\tjr\t$2\n"
          "/* 10 14a010 03e00008 */\tjr\t$ra\n")

    class FakeNet:
        def is_rom(self, proj):
            return True

        def _asm_text(self, fn, proj):
            return fn["asm"].replace("jtbl_", "D_")  # simulate the real rename_tokens

        def reader(self, proj):
            return lambda addr, n: (0x14a010).to_bytes(4, "little") if addr == 0x211000 else None

        _last_diffs = {}

    fn = {"asm": JT, "vram": 0x14a000, "size": 0x20, "id": 1}
    text = "\n".join(RomNetwork._blocks_brief(FakeNet(), fn, {"big_endian": False}, None))
    assert "### Blocks" in text
    assert "jtbl_00211000" in text  # resolved from RAW asm, not the renamed D_ form
