"""silent_run_with_timeout must not return while the timed-out command (or anything
it started) is still running: afl-fuzz locks its output directory, so a follow-up
afl-fuzz started too early fails."""
import os
import time

from muttfuzz import fuzzutil


def _alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # a zombie still "exists"; check its state
    with open("/proc/%d/stat" % pid) as f:
        return f.read().split(")")[-1].split()[0] != "Z"


def test_waits_for_slow_shutdown(tmp_path):
    os.chdir(tmp_path)
    pidfile = tmp_path / "child.pid"
    # child ignores SIGTERM for ~1.5s after it gets it, like a fuzzer writing final stats
    cmd = ("sh -c 'trap \"sleep 1.5; exit 0\" TERM; echo $$ > %s; while true; do sleep 0.1; done'"
           % pidfile)
    t0 = time.time()
    fuzzutil.silent_run_with_timeout(cmd, 1, False, kill_grace=5)
    elapsed = time.time() - t0
    child = int(pidfile.read_text())
    assert not _alive(child)
    assert 2.0 < elapsed < 6.0


def test_kills_processes_that_ignore_sigterm(tmp_path):
    os.chdir(tmp_path)
    pidfile = tmp_path / "child.pid"
    cmd = "sh -c 'trap \"\" TERM; echo $$ > %s; while true; do sleep 0.1; done'" % pidfile
    t0 = time.time()
    fuzzutil.silent_run_with_timeout(cmd, 1, False, kill_grace=1)
    child = int(pidfile.read_text())
    assert not _alive(child)
    assert time.time() - t0 < 5.0


def test_normal_exit_is_fast_and_returns_code(tmp_path):
    os.chdir(tmp_path)
    t0 = time.time()
    assert fuzzutil.silent_run_with_timeout("exit 3", 10, False) == 3
    assert time.time() - t0 < 1.5
