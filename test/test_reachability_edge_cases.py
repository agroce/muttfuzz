"""Reachability sanity warning, and ending the mutant phase cleanly when no
mutant can be generated (previously a RuntimeError traceback that lost the
rest of the budget)."""
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def _toy(d):
    subprocess.check_call(["gcc", "-o", os.path.join(d, "toy"), os.path.join(HERE, "toy.c")])


def test_warns_when_check_fails_on_original(tmp_path):
    _toy(str(tmp_path))
    r = subprocess.run('muttfuzz "./toy" toy --budget 3 --fraction_mutant 0.5 --time_per_mutant 1 '
                       '--reachability_check_cmd "exit 1"', shell=True, cwd=tmp_path,
                       capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "REACHABILITY CHECK FAILS (RETURN CODE 1) ON THE UNMUTATED EXECUTABLE" in r.stdout


def test_no_warning_when_check_passes_on_original(tmp_path):
    _toy(str(tmp_path))
    r = subprocess.run('muttfuzz "./toy" toy --budget 3 --fraction_mutant 0.5 --time_per_mutant 1 '
                       '--reachability_check_cmd "./toy"', shell=True, cwd=tmp_path,
                       capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ON THE UNMUTATED EXECUTABLE" not in r.stdout


def test_all_unreachable_ends_mutant_phase_cleanly(tmp_path):
    _toy(str(tmp_path))
    # "exit 0" == nothing is ever reached, so every function gets marked unreachable
    r = subprocess.run('muttfuzz "./toy" toy --budget 20 --fraction_mutant 0.9 --time_per_mutant 1 '
                       '--reachability_check_cmd "exit 0"', shell=True, cwd=tmp_path,
                       capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ENDING MUTANT PHASE" in r.stdout
    assert "STARTING FINAL FUZZ" in r.stdout
    assert "Traceback" not in r.stderr
"""Reachability sanity warning, and ending the mutant phase cleanly when no
mutant can be generated (previously a RuntimeError traceback that lost the
rest of the budget)."""
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def _toy(d):
    subprocess.check_call(["gcc", "-o", os.path.join(d, "toy"), os.path.join(HERE, "toy.c")])


def test_warns_when_check_fails_on_original(tmp_path):
    _toy(str(tmp_path))
    r = subprocess.run('muttfuzz "./toy" toy --budget 3 --fraction_mutant 0.5 --time_per_mutant 1 '
                       '--reachability_check_cmd "exit 1"', shell=True, cwd=tmp_path,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "REACHABILITY CHECK FAILS (RETURN CODE 1) ON THE UNMUTATED EXECUTABLE" in r.stdout


def test_no_warning_when_check_passes_on_original(tmp_path):
    _toy(str(tmp_path))
    r = subprocess.run('muttfuzz "./toy" toy --budget 3 --fraction_mutant 0.5 --time_per_mutant 1 '
                       '--reachability_check_cmd "./toy"', shell=True, cwd=tmp_path,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ON THE UNMUTATED EXECUTABLE" not in r.stdout


def test_all_unreachable_ends_mutant_phase_cleanly(tmp_path):
    _toy(str(tmp_path))
    # "exit 0" == nothing is ever reached, so every function gets marked unreachable
    r = subprocess.run('muttfuzz "./toy" toy --budget 20 --fraction_mutant 0.9 --time_per_mutant 1 '
                       '--reachability_check_cmd "exit 0"', shell=True, cwd=tmp_path,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ENDING MUTANT PHASE" in r.stdout
    assert "STARTING FINAL FUZZ" in r.stdout
    assert "Traceback" not in r.stderr
