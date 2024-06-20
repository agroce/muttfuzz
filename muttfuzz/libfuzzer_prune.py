import glob
import os
import shutil
import signal
import subprocess
import sys
import time

# Simpler version than in main muttfuzz
def silent_run_with_timeout(cmd, timeout):
    start_P = time.time()
    try:
        with open("cmd_out.txt", 'w') as cmd_out:
            P = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid,
                                 stdout=cmd_out, stderr=cmd_out)
            while (P.poll() is None) and ((time.time() - start_P) < timeout):
                time.sleep(min(0.5, timeout / 10.0)) # Allow for small timeouts
            if P.poll() is None:
                os.killpg(os.getpgid(P.pid), signal.SIGTERM)
        with open("cmd_out.txt", 'r') as cmd_out:
            try:
                cmd_out = cmd_out.read()
            except: #pylint: disable=W0702
                cmd_out = "ERROR READING OUTPUT"
    finally:
        if P.poll() is None:
            print("KILLING SUBPROCESS DUE TO TIMEOUT")
            os.killpg(os.getpgid(P.pid), signal.SIGTERM)

    return (cmd_out, P.returncode)


def main():
    try:
        fuzz_cmd = sys.argv[1]
        timeout = int(sys.argv[2])
        corpus_dir = sys.argv[3]
        new_corpus_dir = sys.argv[4]
        min_pruned = int(sys.argv[5])
        max_pruned = int(sys.argv[6])
    except IndexError:
        print("This tool takes a libfuzzer harness and a corpus, and produces a subset of that corpus that does not fail.")
        print("USAGE: libfuzzer_prune <fuzz_cmd> <timeout> <initial_corpus_dir> <target_corpus_dir> <min_failing> <max_failing>")
        sys.exit(1)

    if not os.path.exists(new_corpus_dir):
        os.mkdir(new_corpus_dir)

    with open(os.path.join(new_corpus_dir, "test"), 'w') as f:
        f.write("0")

    (output, r) = silent_run_with_timeout(fuzz_cmd + " " + os.path.join(new_corpus_dir, "test"), timeout)
    os.remove(os.path.join(new_corpus_dir, "test"))
    if r != 0:
        print("MUTANT KILLED WITH TEST INPUT")
        sys.exit(1)

    pruned = 0

    files = glob.glob(corpus_dir + "/*")
    print("SUBSETTING CORPUS WITH", len(files), "FILES...")

    for f in files:
        shutil.copy(f, os.path.join(new_corpus_dir, os.path.basename(f)))

    while True:
        start = time.time()
        (output, r) = silent_run_with_timeout(fuzz_cmd + " " + new_corpus_dir + "/*", timeout)
        finish = time.time()
        print("TESTS EXECUTED IN", round(finish - start, 2), "SECONDS")
        if r == 0:
            print("TESTS PASS!")
            break
        last_run = None
        for line in output.split("\n"):
            if "Running" in line:
                last_run = line.split()[1]
        print("REMOVING", last_run)
        pruned += 1
        if pruned > max_pruned:
            print("TOO MANY INPUTS FAIL")
            sys.exit(2)
        if last_run is not None:
            os.remove(last_run)

    if pruned < min_pruned:
        print("TOO FEW INPUTS FAIL")
        sys.exit(3)

    print("COMPLETED PRUNING, REMOVED", pruned, "TESTS")
    sys.exit(0)
