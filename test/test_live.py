"""Live mutant switching: patching the running processes of a fork-server-style program.

live_toy forks a child every 20 ms; each child appends f() to a file. f() returns 1
for the original code (x = 1 and `jle` not taken). Inverting the jump in the running
parent makes every child forked afterwards return 2, without restarting anything, and
the on-disk binary is never modified.
"""
import os
import subprocess
import time

from muttfuzz import live, mutate

HERE = os.path.dirname(os.path.abspath(__file__))


def _last_values(path, n=5):
    with open(path) as f:
        return [line.strip() for line in f.readlines()[-n:]]


def _wait_for(path, value, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if os.path.exists(path) and _last_values(path) == [value] * 5:
            return True
        time.sleep(0.05)
    return False


def test_live_patch_and_revert(tmp_path):
    exe = str(tmp_path / "live_toy")
    subprocess.check_call(["gcc", "-O0", "-g", "-o", exe, os.path.join(HERE, "live_toy.c")])
    jumps, _function_map, _reach = mutate.get_jumps(exe, ["f"], [], [], [], False, False)
    (loc,) = [k for k, v in jumps.items() if v["opcode"] == "jle"]
    with open(exe, "rb") as f:
        original = bytearray(f.read())
    mutant = bytearray(original)
    mutant[loc] ^= 1  # 0x7e jle -> 0x7f jg
    patches = live.diff(original, mutant)
    assert patches == [(loc, bytes([original[loc] ^ 1]))]

    out = str(tmp_path / "values.txt")
    proc = subprocess.Popen([exe, out])
    try:
        assert _wait_for(out, "1")
        patcher = live.LivePatcher(exe, proc.pid)
        assert patcher.apply(patches) >= 1
        assert _wait_for(out, "2"), "mutant not live in newly forked children"
        patcher.apply(live.inverse(original, patches))
        assert _wait_for(out, "1"), "revert not live"
        with open(exe, "rb") as f:
            assert f.read() == bytes(original)  # disk untouched
    finally:
        proc.kill()
        proc.wait()


def test_diff_merges_runs_and_inverse():
    a = bytearray(200000)
    b = bytearray(a)
    b[70000:70003] = b"\x01\x02\x03"
    b[199999] = 7
    d = live.diff(a, b)
    assert d == [(70000, b"\x01\x02\x03"), (199999, b"\x07")]
    assert live.inverse(a, d) == [(70000, b"\x00\x00\x00"), (199999, b"\x00")]


def test_muttfuzz_live_end_to_end(tmp_path):
    """muttfuzz --live: one long-running 'fuzzer' (live_toy) for the whole budget, with
    mutants of f() switched in and out of it; it is killed at the end of the budget."""
    exe = str(tmp_path / "live_toy")
    subprocess.check_call(["gcc", "-O0", "-g", "-o", exe, os.path.join(HERE, "live_toy.c")])
    out = str(tmp_path / "values.txt")
    r = subprocess.run('muttfuzz "./live_toy %s" live_toy --live --budget 8 --initial_budget 1 '
                       '--time_per_mutant 1 --fraction_mutant 0.7 --only_mutate f --seed 1' % out,
                       shell=True, cwd=tmp_path, capture_output=True, text=True, timeout=120, check=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SWITCHED" in r.stdout
    assert "STARTING FINAL FUZZ" in r.stdout
    assert os.path.exists(out), r.stdout[-3000:]
    values = open(out).read().split()
    assert "1" in values and "2" in values  # original and at least one live mutant ran
    assert values[-1] == "1"  # original restored for the final phase
    time.sleep(0.2)
    alive = subprocess.run(["pgrep", "-f", exe], capture_output=True, text=True, check=False).stdout
    assert alive.strip() == ""  # live fuzzer killed at the end


def test_live_reapplies_to_restarted_processes(tmp_path):
    """A 'fuzzer' that restarts the target every 2 s (like a wrapper restarting libFuzzer
    after a crash): the mutant must still be live in the restarted processes."""
    exe = str(tmp_path / "live_toy")
    subprocess.check_call(["gcc", "-O0", "-g", "-o", exe, os.path.join(HERE, "live_toy.c")])
    out = str(tmp_path / "values.txt")
    cmd = "while true; do timeout 2 ./live_toy %s; done" % out
    r = subprocess.run('muttfuzz "%s" live_toy --live --budget 9 --time_per_mutant 6 --fraction_mutant 0.5 '
                       '--only_mutate f --seed 1' % cmd,
                       shell=True, cwd=tmp_path, capture_output=True, text=True, timeout=120, check=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "CHANGING TO jg" in r.stdout  # seed 1: the first mutant inverts the jump
    values = open(out).read().split()
    # during the 6 s mutant window the toy is restarted ~3 times; the mutant must cover
    # most of the window, not just the first process
    assert values.count("2") > 150, values.count("2")
