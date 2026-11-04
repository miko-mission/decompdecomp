"""ROM join: an agent says two adjacent symbols are one function the analysis cut; once NOT_C_AGENTS agents of
NOT_C_MODELS models agree, the pieces are merged back into one (engine.join_functions). ROM projects previously
had no merge at all (join_functions was fork-only), so over-split fragments got bodied/stubbed. Validated as a
split->join round-trip: splitting a function then joining the pieces restores the original bytes and extent."""

import shutil

import pytest

from decompnet import toolchains
from decompnet.app.engine import RomNetwork
from decompnet.network import NetworkError

from .test_rom import built  # noqa: F401  (fixture that builds the demo ROM)

pytestmark = pytest.mark.skipif(toolchains.installed("gcc-2.7.2-kmc") is None or not shutil.which("ld.lld"),
                                reason="needs gcc-2.7.2-kmc and ld.lld to build the demo ROM")

SLUG = "demo-quest-64"
FN = "func_800007C4"      # import ran exit() (noreturn) straight into clamp_s32 at 0x800007D0
TAIL = "func_800007D0"


@pytest.fixture
def net(built, tmp_path):  # noqa: F811  (fresh per test: these tests mutate the function list)
    net = RomNetwork(tmp_path / "decomp.db", tmp_path)
    assert net.import_rom(built, confirmed=True, log=lambda *_: None) == SLUG
    return net


def _agree(net, a, b, names=("aa-1", "aa-2", "bb-1")):  # 3 agents, 2 models (model_of strips -N)
    out = ""
    for name in names:
        ag, _ = net.local_agent(name)
        out = net.join_functions(ag, SLUG, a, b, "no prologue; uses registers set before it; runs straight in")
    return out


def test_join_restores_a_split_function(net):
    agent, _ = net.local_agent("tester")
    orig = net._function(FN, SLUG)
    orig_size, orig_target = orig["size"], orig["target"]
    assert "split" in net.split_function(agent, SLUG, FN, "0x800007D0")
    assert net._function(FN, SLUG)["size"] < orig_size          # head only now
    out = _agree(net, FN, TAIL)
    assert out.startswith("✅"), out
    joined = net._function(FN, SLUG)
    assert joined["size"] == orig_size, (joined["size"], orig_size)
    assert joined["target"] == orig_target                      # original bytes restored
    assert joined["status"] != "matched"
    assert net.store.one("SELECT 1 FROM functions WHERE project_id=? AND name=?",
                         orig["project_id"], TAIL) is None       # tail merged into the head, removed


def test_vote_below_threshold_does_not_merge(net):
    agent, _ = net.local_agent("tester")
    net.split_function(agent, SLUG, FN, "0x800007D0")
    head_size = net._function(FN, SLUG)["size"]
    ag, _ = net.local_agent("solo-1")
    out = net.join_functions(ag, SLUG, FN, TAIL, "looks joined")
    assert "counted" in out.lower()
    assert net._function(FN, SLUG)["size"] == head_size         # unchanged until enough agree


def test_refuses_non_adjacent(net):
    agent, _ = net.local_agent("tester")
    with pytest.raises(NetworkError):                           # func_80000808 is far away, not the next symbol
        net.join_functions(agent, SLUG, FN, "func_80000808", "not adjacent")


def _relabel(net, name, unit, rom_offset=None):
    with net.store.tx() as db:
        if rom_offset is None:
            db.execute("UPDATE functions SET unit=? WHERE name=?", (unit, name))
        else:
            db.execute("UPDATE functions SET unit=?, rom_offset=? WHERE name=?", (unit, rom_offset, name))


def test_join_across_overlay_units_when_rom_contiguous(net):
    # An over-split cut can leave head and tail in different unit strings though they are one run of an overlay:
    # the head resolves to its source file, the orphaned tail keeps only the overlay label. ROM contiguity proves
    # they are the same run, so the join is allowed across the unit mismatch.
    agent, _ = net.local_agent("tester")
    orig = net._function(FN, SLUG)
    orig_size, orig_target = orig["size"], orig["target"]
    net.split_function(agent, SLUG, FN, "0x800007D0")
    _relabel(net, TAIL, "ovl_demo_fragment")                    # tail now a different unit; rom_offset unchanged
    assert net._function(FN, SLUG)["unit"] != net._function(TAIL, SLUG)["unit"]
    out = _agree(net, FN, TAIL)
    assert out.startswith("✅"), out                             # rom-contiguous => allowed
    joined = net._function(FN, SLUG)
    assert joined["size"] == orig_size, (joined["size"], orig_size)
    assert joined["target"] == orig_target                      # original bytes restored
    assert net.store.one("SELECT 1 FROM functions WHERE project_id=? AND name=?",
                         orig["project_id"], TAIL) is None       # tail merged in, removed


def test_refuses_cross_unit_when_not_rom_contiguous(net):
    # Different unit AND a different ROM region = overlay aliasing (two overlays at one vram), not a continuation.
    agent, _ = net.local_agent("tester")
    net.split_function(agent, SLUG, FN, "0x800007D0")
    tail = net._function(TAIL, SLUG)
    _relabel(net, TAIL, "ovl_elsewhere", rom_offset=(tail["rom_offset"] or 0) + 0x40000)
    ag, _ = net.local_agent("solo-1")
    with pytest.raises(NetworkError):
        net.join_functions(ag, SLUG, FN, TAIL, "aliased, not a continuation")


def test_join_selects_by_rom_run_not_the_shared_vram_window(net):
    # Overlays alias the same vram within one unit (different ROM copies). The merge must pick the pieces by their
    # ROM run, or it would sweep in an aliased copy sitting at the same address+unit and delete it.
    agent, _ = net.local_agent("tester")
    orig = net._function(FN, SLUG)
    pid = orig["project_id"]
    net.split_function(agent, SLUG, FN, "0x800007D0")
    head = net._function(FN, SLUG)
    with net.store.tx() as db:   # a byte-identical alias of the head: same unit+vram, a far-away ROM copy, matched
        db.execute("INSERT INTO functions(project_id,name,size,n_insns,target,relocs,asm,seed,unit,vram,rom_offset,"
                   "status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                   (pid, "alias_head", head["size"], head["n_insns"], head["target"], head["relocs"], head["asm"],
                    None, head["unit"], head["vram"], (head["rom_offset"] or 0) + 0x100000, "matched"))
    net._syms.pop(pid, None)
    out = _agree(net, FN, TAIL)
    assert out.startswith("✅"), out
    assert net._function(FN, SLUG)["size"] == orig["size"]        # head+tail rejoined, nothing else
    assert net.store.one("SELECT 1 FROM functions WHERE project_id=? AND name=?", pid, TAIL) is None
    alias = net.store.one("SELECT status FROM functions WHERE project_id=? AND name=?", pid, "alias_head")
    assert alias is not None and alias["status"] == "matched"     # the aliased copy was NOT swept into the merge


def test_vote_nudge_targets_a_fresh_model_for_a_one_model_join(net):
    # VOTE_NUDGE prototype: a sub-quorum join vote (one model) marks the head; the selector routes a different-model
    # agent to it and skips the model that already voted -- the quorum's second opinion without a random assignment.
    agent, _ = net.local_agent("tester")
    net.split_function(agent, SLUG, FN, "0x800007D0")
    ag, _ = net.local_agent("aa-1")
    assert "counted" in net.join_functions(ag, SLUG, FN, TAIL, "no prologue; runs straight in").lower()
    pid = net._function(FN, SLUG)["project_id"]
    fn_id = net._function(FN, SLUG)["id"]
    assert fn_id in net._vote_needs_model(pid, "bb")       # a model not yet among the voters is routed here
    assert fn_id not in net._vote_needs_model(pid, "aa")   # the model that already voted is not


def test_vote_nudge_flag_floats_the_pending_vote_in_a_claim(net, monkeypatch):
    # With the flag on, a fresh-model agent claiming (no function named) is routed to the pending-vote head.
    import decompnet.network as network
    monkeypatch.setattr(network, "VOTE_NUDGE", True)
    agent, _ = net.local_agent("tester")
    net.split_function(agent, SLUG, FN, "0x800007D0")
    ag, _ = net.local_agent("aa-1")
    net.join_functions(ag, SLUG, FN, TAIL, "no prologue; runs straight in")   # sub-quorum, model 'aa'
    bb, _ = net.local_agent("bb-1")                                           # a model not among the voters
    assert "func_800007C4" in net.claim(bb, SLUG)                            # floated to the pending-vote head


def test_vote_nudge_is_off_without_the_flag(net):
    # Off by default: the selector still marks the head (harmless metadata), but claim ordering is unchanged, so the
    # nudge never fires unless DECOMP_VOTE_NUDGE is set. (The flag gates only claim_row; _vote_needs_model is pure.)
    import decompnet.network as network
    assert network.VOTE_NUDGE is False


def test_vote_nudge_cap_cools_off_a_non_converging_join(net):
    # The cap: once VOTE_NUDGE_CAP distinct fresh models have claimed a short join without corroborating, stop
    # routing more scarce models to it (the fixation the live watch showed).
    import time as _time
    from decompnet.network import VOTE_NUDGE_CAP
    agent, _ = net.local_agent("tester")
    net.split_function(agent, SLUG, FN, "0x800007D0")
    ag, _ = net.local_agent("aa-1")
    net.join_functions(ag, SLUG, FN, TAIL, "no prologue; runs straight in")   # sub-quorum, model 'aa'
    pid = net._function(FN, SLUG)["project_id"]
    fn_id = net._function(FN, SLUG)["id"]
    assert fn_id in net._vote_needs_model(pid, "dd")                           # nudged before the cap
    fresh = [f"m{i}-1" for i in range(VOTE_NUDGE_CAP)]                         # that many distinct fresh models look
    with net.store.tx() as db:
        for nm in fresh:
            a, _ = net.local_agent(nm)
            db.execute("INSERT INTO events(project_id, agent_id, kind, detail, created_at) VALUES(?,?,'claim',?,?)",
                       (pid, a.id, "func_800007C4", _time.time()))
    assert fn_id not in net._vote_needs_model(pid, "dd")                       # cooled off: no longer nudged


def test_second_opinion_strategy_pulls_from_the_queue(net, monkeypatch):
    import decompnet.network as network
    monkeypatch.setattr(network, "VOTE_NUDGE", True)
    agent, _ = net.local_agent("tester")
    net.split_function(agent, SLUG, FN, "0x800007D0")
    ag, _ = net.local_agent("aa-1")
    net.join_functions(ag, SLUG, FN, TAIL, "no prologue; runs straight in")   # sub-quorum, model 'aa'
    bb, _ = net.local_agent("bb-1")
    assert "func_800007C4" in net.claim(bb, SLUG, strategy="second_opinion")  # pulled the short-vote head


def test_second_opinion_falls_back_when_the_queue_is_empty(net, monkeypatch):
    # The voter's own model has an empty queue (it already voted); second_opinion must still hand it work, not fail.
    import decompnet.network as network
    monkeypatch.setattr(network, "VOTE_NUDGE", True)
    agent, _ = net.local_agent("tester")
    net.split_function(agent, SLUG, FN, "0x800007D0")
    ag, _ = net.local_agent("aa-1")
    net.join_functions(ag, SLUG, FN, TAIL, "no prologue; runs straight in")   # model 'aa' now in vote_models
    aa2, _ = net.local_agent("aa-2")                                          # same model, empty queue
    out = net.claim(aa2, SLUG, strategy="second_opinion")
    assert "CLAIMED" in out                                                   # fell back to a normal claim
