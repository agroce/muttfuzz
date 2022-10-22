from datetime import datetime
import os
import signal
import subprocess
import time

import muttfuzz.mutate as mutate


def restore_executable(executable, executable_code):
    # We do this because it could still be busy if fuzzer hasn't shut down yet
    with open("/tmp/new_executable", 'wb') as f:
        f.write(executable_code)
    os.rename("/tmp/new_executable", executable)
    subprocess.check_call(['chmod', '+x', executable])

def silent_run_with_timeout(cmd, timeout):
    dnull = open(os.devnull, 'w')
    start_P = time.time()
    try:
        with open("cmd_errors.txt", 'w') as cmd_errors:
            P = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid, stdout=dnull, stderr=cmd_errors)
            while (P.poll() is None) and ((time.time() - start_P) < timeout):
                time.sleep(0.5)
            if P.poll() is None:
                os.killpg(os.getpgid(P.pid), signal.SIGTERM)
        with open("cmd_errors.txt", 'r') as cmd_errors:
            cmd_errors_out = cmd_errors.read()
        if len(cmd_errors_out) > 0:
            print("ERRORS:")
            print(cmd_errors_out)
    finally:
        if P.poll() is None:
            os.killpg(os.getpgid(P.pid), signal.SIGTERM)        

        
def fuzz_with_mutants(fuzzer_cmd, executable, budget,
                      time_per_mutant, fraction_mutant,
                      initial_fuzz_cmd="", initial_budget=0,
                      post_mutant_cmd="",
                      status_cmd="", order=1):
    executable_code = mutate.get_code(executable)
    executable_jumps = mutate.get_jumps(executable)
    start_fuzz = time.time()
    mutant_no = 1
    try:
        if initial_fuzz_cmd != "":
            print("=" * 10,
                  datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'),
                  "=" * 10)
            print("RUNNING INITIAL FUZZING...")
            silent_run_with_timeout(initial_fuzz_cmd, initial_budget)
            if status_cmd != "":
                print("INITIAL STATUS:")
                subprocess.call(status_cmd, shell=True)

        while ((time.time() - start_fuzz) - initial_budget) < (budget * fraction_mutant):
            print("=" * 10,
                  datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'),
                  "=" * 10)
            print(round(time.time() - start_fuzz, 2),
                  "ELAPSED: GENERATING MUTANT #" + str(mutant_no))
            mutant_no += 1
            # make a new mutant of the executable; rename avoids hitting a busy executable
            mutate.mutate_from(executable_code, executable_jumps, "/tmp/new_executable", order=order)
            os.rename("/tmp/new_executable", executable)
            subprocess.check_call(['chmod', '+x', executable])
            print("FUZZING MUTANT...")
            start_run = time.time()
            silent_run_with_timeout(fuzzer_cmd, time_per_mutant)
            print("FINISHED FUZZING IN", round(time.time() - start_run, 2), "SECONDS")
            if post_mutant_cmd != "":
                subprocess.call(post_mutant_cmd, shell=True)
            if status_cmd != "":
                print("STATUS:")
                subprocess.call(status_cmd, shell=True)

        print(datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))
        print(round(time.time() - start_fuzz, 2), "ELAPSED: STARTING FINAL FUZZ")
        restore_executable(executable, executable_code)
        silent_run_with_timeout(fuzzer_cmd, budget - (time.time() - start_fuzz))
        print("COMPLETED ALL FUZZING AFTER", round(time.time() - start_fuzz, 2), "SECONDS")
        if status_cmd != "":
            print("FINAL STATUS:")
            subprocess.call(status_cmd, shell=True)
    finally:
        # always restore the original binary!
        restore_executable(executable, executable_code)
