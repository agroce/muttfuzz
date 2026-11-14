"""Frontier-targeted mutant selection (--frontier_check)."""
import os
import subprocess

from muttfuzz import frontier, mutate

HERE = os.path.dirname(os.path.abspath(__file__))


def _setup(tmp_path):
    exe = str(tmp_path / "frontier_toy")
    subprocess.check_call(["gcc", "-O0", "-g", "-o", exe, os.path.join(HERE, "frontier_toy.c")])
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for name, data in (("a", b"abc"), ("b", b"hello"), ("c", b"Y")):
        (corpus / name).write_bytes(data)
    return exe, corpus


def _finder(exe, corpus, tmp_path):
    jumps, _function_map, function_reach = mutate.get_jumps(exe, ["check"], [], [], [], False, False)
    with open(exe, "rb") as f:
        code = bytearray(f.read())
    work = tmp_path / "work"
    work.mkdir()
    cmd = "%s %s/*" % (exe, corpus)

    def run_check():
        return subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return frontier.FrontierFinder(code, jumps, function_reach, exe, str(work), run_check), jumps, code


def test_classify(tmp_path):
    exe, corpus = _setup(tmp_path)
    finder, jumps, code = _finder(exe, corpus, tmp_path)
    by_op = {v["opcode"]: k for k, v in jumps.items()}
    # `n > 0` (jle, never taken) jumps to code the corpus reaches anyway: not a frontier
    assert finder.classify(by_op["jle"], 1) == "target_covered"
    # `buf[0] == 'X'` (jne, always taken): the rare() side is the frontier
    assert finder.classify(by_op["jne"], 1) == "taken"
    with open(exe, "rb") as f:
        assert f.read() == bytes(code)  # executable restored after probing


def test_find_and_force(tmp_path):
    exe, corpus = _setup(tmp_path)
    finder, jumps, code = _finder(exe, corpus, tmp_path)
    loc, status = finder.find(1, max_probes=20)
    assert jumps[loc]["opcode"] == "jne" and status == "taken"
    new_data = finder.mutant(loc, status)
    assert new_data == mutate.NOP * 2
    mutant = bytearray(code)
    mutant[loc:loc + len(new_data)] = new_data
    mexe = str(tmp_path / "mutant")
    with open(mexe, "wb") as f:
        f.write(mutant)
    os.chmod(mexe, 0o755)
    out = str(tmp_path / "rare.txt")
    subprocess.check_call([mexe, str(corpus / "a")], env=dict(os.environ, FRONTIER_OUT=out))
    assert open(out).read() == "RARE\n"  # the mutant reaches the code the corpus never did


def test_both_sides_once_seen_is_cached(tmp_path):
    exe, corpus = _setup(tmp_path)
    (corpus / "x").write_bytes(b"Xyz")  # now the corpus takes both sides of the 'X' check
    finder, jumps, _code = _finder(exe, corpus, tmp_path)
    by_op = {v["opcode"]: k for k, v in jumps.items()}
    assert finder.classify(by_op["jne"], 1) == "both"
    assert finder.find(2, max_probes=20) is None  # no frontier left in check()
    probes = finder.probes_run
    assert finder.find(3, max_probes=20) is None
    assert finder.probes_run == probes  # nothing re-probed: both jumps are settled


def test_muttfuzz_frontier_end_to_end(tmp_path):
    exe, _corpus = _setup(tmp_path)
    out = str(tmp_path / "rare.txt")
    r = subprocess.run('muttfuzz "FRONTIER_OUT=%s ./frontier_toy corpus/a" frontier_toy --only_mutate check '
                       '--frontier_check --reachability_check_cmd "./frontier_toy corpus/*" '
                       '--budget 6 --time_per_mutant 1 --fraction_mutant 0.8' % out,
                       shell=True, cwd=tmp_path, capture_output=True, text=True, timeout=120, check=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "FRONTIER JUMP" in r.stdout and "ALWAYS TAKES THIS JUMP" in r.stdout
    assert "RARE" in open(out).read()
    assert os.path.exists(exe)


def test_frontier_fraction_zero_skips_search(tmp_path):
    _exe, _corpus = _setup(tmp_path)
    out = str(tmp_path / "rare.txt")
    r = subprocess.run('muttfuzz "FRONTIER_OUT=%s ./frontier_toy corpus/a" frontier_toy --only_mutate check '
                       '--frontier_check --frontier_fraction 0 --reachability_check_cmd "./frontier_toy corpus/*" '
                       '--budget 4 --time_per_mutant 1 --fraction_mutant 0.8' % out,
                       shell=True, cwd=tmp_path, capture_output=True, text=True, timeout=120, check=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "NOT SEARCHING THE FRONTIER" in r.stdout
    assert "FRONTIER JUMP (" not in r.stdout
    assert "CHECKING REACHABILITY" in r.stdout or "REACHABLE" in r.stdout


def test_frontier_fraction_range(tmp_path):
    _setup(tmp_path)
    r = subprocess.run('muttfuzz "./frontier_toy corpus/a" frontier_toy --only_mutate check '
                       '--frontier_check --frontier_fraction 1.5 --reachability_check_cmd "./frontier_toy corpus/*" '
                       '--budget 2 --time_per_mutant 1',
                       shell=True, cwd=tmp_path, capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode != 0
    assert "frontier_fraction" in r.stdout + r.stderr
