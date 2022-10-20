from datetime import datetime
import os
import signal
import subprocess
import time
import mutate

def silent_run_with_timeout(cmd, timeout):
    start_P = time.time()
    P = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid, stdout=dnull, stderr=dnull)
    while (P.poll() is None) and ((time.time() - start_P) < timeout):
        time.sleep(0.5)
    if P.poll() is None:
        os.killpg(os.getpgid(P.pid), signal.SIGTERM)

def fuzz_with_mutants(fuzzer_cmd, executable, total_budget, time_per_mutant, fraction_mutant):
    executable_code = mutate.get_code(executable)
    executable_jumps = mutate.get_jumps(executable)
    start_fuzz = time.time()
    mutant_no = 1
    try:
        while (time.time() - start_fuzz) < total_budget:
            if (time.time() - start_fuzz) < (total_budget * fraction_mutant):
                print(datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')))
                print(round(time.datetime.time() - start_fuzz, 2),
                      "ELAPSED: GENERATING MUTANT #", mutant_no)
                mutant_no += 1
                # make a new mutant of the executable            
                mutate.mutate_from(executable_code, executable_jumps, executable)
                print("FUZZING MUTANT...")
                silent_run_with_timeout(fuzzer_cmd, time_per_mutant)
            else:
                print(datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')))
                print(round(time.datetime.time() - start_fuzz, 2), "ELAPSED: STARTING FINAL FUZZ")  
                with open(executable, "wb") as f:
                    f.write(executable_code)
                silent_run_with_timeout(fuzzer_cmd, total_budget - (time.time() - start_fuzz))
    finally:
        # always restore the original binary!
        with open(executable, "wb") as f:
            f.write(executable_code)
