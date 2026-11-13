"""muttfuzz must not depend on fixed /tmp paths: mutants are moved into place with
os.rename, which fails when the executable is on another filesystem, and fixed
paths collide between concurrent runs."""
import glob
import os
import shutil
import subprocess

import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def _run_score(d):
    subprocess.check_call(["gcc", "-o", os.path.join(d, "toy"), os.path.join(HERE, "toy.c")])
    r = subprocess.run('muttfuzz "./toy" toy --score --avoid_repeats --stop_on_repeat --repeat_retries 2000',
                       shell=True, cwd=d, capture_output=True, text=True, check=False)
    return r


def test_no_fixed_tmp_paths_and_cleanup(tmp_path):
    if os.path.exists("/tmp/new_executable"):
        raise unittest.SkipTest("/tmp/new_executable left over from an older muttfuzz")
    r = _run_score(str(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "FINAL MUTATION SCORE OVER 14 EXECUTED MUTANTS: 57.14%" in r.stdout
    assert not os.path.exists("/tmp/new_executable")
    assert not glob.glob(str(tmp_path / ".muttfuzz_*"))


def test_executable_on_another_filesystem():
    if not os.path.isdir("/dev/shm") or os.stat("/dev/shm").st_dev == os.stat("/tmp").st_dev:
        raise unittest.SkipTest("need /dev/shm on a different filesystem from /tmp")
    d = "/dev/shm/muttfuzz_test_%d" % os.getpid()
    os.makedirs(d)
    try:
        r = _run_score(d)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "FINAL MUTATION SCORE OVER 14 EXECUTED MUTANTS: 57.14%" in r.stdout
    finally:
        shutil.rmtree(d, ignore_errors=True)
