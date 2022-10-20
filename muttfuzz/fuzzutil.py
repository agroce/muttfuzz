from datetime import datetime
import os
import signal
import subprocess
import time
import mutate


def silent_run_with_timeout(cmd, timeout):
    dnull = open(os.devnull, 'w')
    start_P = time.time()
    try:
        P = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid, stdout=dnull, stderr=dnull)
        while (P.poll() is None) and ((time.time() - start_P) < timeout):
            time.sleep(0.5)
        if P.poll() is None:
            os.killpg(os.getpgid(P.pid), signal.SIGTERM)
    finally:
        if P.poll() is None:
            os.killpg(os.getpgid(P.pid), signal.SIGTERM)        

        
def fuzz_with_mutants(fuzzer_cmd, executable, budget,
                      time_per_mutant, fraction_mutant,
                      status_cmd="", order=1):
    executable_code = mutate.get_code(executable)
    executable_jumps = mutate.get_jumps(executable)
    start_fuzz = time.time()
    mutant_no = 1
    try:
        while (time.time() - start_fuzz) < budget:
            if (time.time() - start_fuzz) < (budget * fraction_mutant):
                print("=" * 10,
                      datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'),
                      "=" * 10)
                print(round(time.time() - start_fuzz, 2),
                      "ELAPSED: GENERATING MUTANT #", mutant_no)
                mutant_no += 1
                # make a new mutant of the executable            
                mutate.mutate_from(executable_code, executable_jumps, executable, order=order)
                print("FUZZING MUTANT...")
                start_run = time.time()
                silent_run_with_timeout(fuzzer_cmd, time_per_mutant)
                print("FINISHED FUZZING IN", round(time.time() - start_run, 2), "SECONDS")
                if status_cmd != "":
                    subprocess.call(status_cmd, shell=True)
            else:
                print(datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))
                print(round(time.datetime.time() - start_fuzz, 2), "ELAPSED: STARTING FINAL FUZZ")  
                with open(executable, "wb") as f:
                    f.write(executable_code)
                silent_run_with_timeout(fuzzer_cmd, budget - (time.time() - start_fuzz))
    finally:
        # always restore the original binary!
        with open(executable, "wb") as f:
            f.write(executable_code)
