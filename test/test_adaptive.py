"""Adaptive time per mutant (--progress_cmd): a mutant runs --time_per_mutant seconds and is
extended one --progress_window at a time while the progress command's number grows."""
import os
import re
import subprocess
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def _durations(stdout):
    return [float(x) for x in re.findall(r"MUTANT RAN FOR ([0-9.]+) SECONDS", stdout)]


def _run(tmp_path, grow_for, live):
    subprocess.check_call(["gcc", "-O0", "-g", "-o", str(tmp_path / "live_toy"), os.path.join(HERE, "live_toy.c")])
    counter = tmp_path / "progress"
    counter.write_text("0\n")
    stop = threading.Event()

    def grow():  # "fuzzer progress": grows for grow_for seconds after start, then stalls
        t0, n = time.time(), 0
        while not stop.is_set():
            if time.time() - t0 < grow_for:
                n += 1
                counter.write_text("corpus_count : %d\n" % n)
            time.sleep(0.2)

    t = threading.Thread(target=grow, daemon=True)
    t.start()
    try:
        r = subprocess.run('muttfuzz "./live_toy values.txt" live_toy --only_mutate f %s '
                           '--budget 30 --time_per_mutant 2 --progress_window 1 --max_time_per_mutant 10 '
                           '--fraction_mutant 0.9 --progress_cmd "cat progress"' % ("--live" if live else ""),
                           shell=True, cwd=tmp_path, capture_output=True, text=True, timeout=120, check=False)
    finally:
        stop.set()
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout


def test_extends_while_progressing_then_stops(tmp_path):
    out = _run(tmp_path, grow_for=6, live=False)
    d = _durations(out)
    assert "EXTENDING MUTANT" in out
    assert 4.5 <= d[0] <= 8.5  # 2 s minimum, extended while progress lasts (~6 s), then stopped
    assert all(x < 3.5 for x in d[1:])  # no progress afterwards: later mutants get the minimum


def test_capped_at_max_time_live(tmp_path):
    out = _run(tmp_path, grow_for=100, live=True)
    d = _durations(out)
    assert "MUTANT REACHED ITS TIME LIMIT WHILE STILL MAKING PROGRESS" in out
    assert 9.0 <= d[0] <= 11.5
