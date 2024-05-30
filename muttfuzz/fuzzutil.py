from datetime import datetime
import os
import signal
import subprocess
import time
from contextlib import contextmanager

from muttfuzz import mutate


class TimeoutException(Exception):
    """"Exception thrown when timeouts occur"""


@contextmanager
def time_limit(seconds):
    """Method to define a time limit before throwing exception"""

    def signal_handler(signum, frame):
        raise TimeoutException("Timed out!")

    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)


def restore_executable(executable, executable_code):
    # We do this because it could still be busy if fuzzer hasn't shut down yet
    with open("/tmp/restore_executable", 'wb') as f:
        f.write(executable_code)
    os.rename("/tmp/restore_executable", executable)
    subprocess.check_call(['chmod', '+x', executable])


def silent_run_with_timeout(cmd, timeout):
    dnull = open(os.devnull, 'w')
    print("*" * 80)
    print("EXECUTING", cmd)
    start_P = time.time()
    try:
        with open("cmd_errors.txt", 'w') as cmd_errors:
            P = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid,
                                 stdout=dnull, stderr=cmd_errors)
            while (P.poll() is None) and ((time.time() - start_P) < timeout):
                time.sleep(min(0.5, timeout / 10.0)) # Allow for small timeouts
            if P.poll() is None:
                os.killpg(os.getpgid(P.pid), signal.SIGTERM)
        with open("cmd_errors.txt", 'r') as cmd_errors:
            try:
                cmd_errors_out = cmd_errors.read()
            except:
                cmd_errors_out = "ERROR READING OUTPUT"
        if len(cmd_errors_out) > 0:
            print("OUTPUT (TRUNCATED TO LAST 20 LINES):")
            print("\n".join(cmd_errors_out.split("\n")[-20:]))
    finally:
        if P.poll() is None:
            print("KILLING SUBPROCESS DUE TO TIMEOUT")
            os.killpg(os.getpgid(P.pid), signal.SIGTERM)
    print("COMPLETE IN", round(time.time() - start_P, 2), "SECONDS")
    print("*" * 80)

    return P.returncode


def fuzz_with_mutants(fuzzer_cmd, executable, budget, time_per_mutant, fraction_mutant,
                      only_mutate=[],
                      avoid_mutating=[],
                      reachability_check_cmd="",
                      reachability_check_timeout=2.0,
                      prune_mutant_cmd="",
                      prune_mutant_timeout=2.0,
                      initial_fuzz_cmd="",
                      initial_budget=0,
                      post_initial_cmd="",
                      post_mutant_cmd="",
                      post_mutant_timeout=2.0,
                      status_cmd="",
                      order=1,
                      score=False,
                      save_mutants=""):
    executable_code = mutate.get_code(executable)
    executable_jumps = mutate.get_jumps(executable, only_mutate, avoid_mutating)
    print("FOUND", len(executable_jumps), "JUMPS")
    print("JUMPS BY SECTION:")
    section_jumps = {}
    for jump in executable_jumps:
        if jump["section_name"] not in section_jumps:
            section_jumps[jump["section_name"]] = [jump]
        else:
            section_jumps[jump["section_name"]].append(jump)
    for section in section_jumps:
        print(section, len(section_jumps[section]))
    print()
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
            if post_initial_cmd != "":
                subprocess.call(post_initial_cmd, shell=True)

        if reachability_check_cmd != "":
            reachability_filename = "/tmp/reachability_executable"
            reachability_checks = 0.0
            reachability_hits = 0.0
        else:
            reachability_filename = ""
        if score:
            mutants_run = 0.0
            mutants_killed = 0.0
            fraction_mutant = 1.0 # No final fuzz for mutation score estimation!
        while ((time.time() - start_fuzz) - initial_budget) < (budget * fraction_mutant):
            print("=" * 10,
                  datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'),
                  "=" * 10)
            print(round(time.time() - start_fuzz, 2),
                  "ELAPSED: GENERATING MUTANT #" + str(mutant_no))
            mutant_no += 1
            # make a new mutant of the executable; rename avoids hitting a busy executable
            mutate.mutate_from(executable_code, executable_jumps, "/tmp/new_executable", order=order,
                               reachability_filename=reachability_filename, save_mutants=save_mutants,
                               save_count = mutant_no)
            mutant_ok = True
            if reachability_check_cmd != "":
                print("CHECKING REACHABILITY")
                reachability_checks += 1.0
                os.rename(reachability_filename, executable)
                subprocess.check_call(['chmod', '+x', executable])
                r = silent_run_with_timeout(reachability_check_cmd, reachability_check_timeout)
                restore_executable(executable, executable_code)
                if r == 0:
                    print("MUTANT IS NOT REACHABLE (RETURN CODE 0)")
                    mutant_ok = False
                else:
                    reachability_hits += 1.0
                print ("RUNNING COVERAGE ESTIMATE OVER", int(reachability_checks), "MUTANTS:",
                       str(round((reachability_hits / reachability_checks) * 100.0, 2)) + "%")
            if mutant_ok:
                os.rename("/tmp/new_executable", executable)
                subprocess.check_call(['chmod', '+x', executable])
                if prune_mutant_cmd != "":
                    print("PRUNING MUTANT...")
                    r = silent_run_with_timeout(prune_mutant_cmd, prune_mutant_timeout)
                    if r != 0:
                        print("CHECK FAILED WITH RETURN CODE", r)
                        mutant_ok = False
            if mutant_ok:
                print("FUZZING MUTANT...")
                start_run = time.time()
                r = silent_run_with_timeout(fuzzer_cmd, time_per_mutant)
                if score:
                    mutants_run += 1
                    if (r != 0):
                        mutants_killed += 1
                        print ("** MUTANT KILLED **")
                    else:
                        print ("** MUTANT NOT KILLED **")
                    print ("RUNNING MUTATION SCORE ON", int(mutants_run), "MUTANTS:",
                           str(round((mutants_killed / mutants_run) * 100.0, 2)) + "%")
                print("FINISHED FUZZING IN", round(time.time() - start_run, 2), "SECONDS")
                if post_mutant_cmd != "":
                    restore_executable(executable, executable_code) # Might need original for post
                    print("RUNNING POST-MUTANT COMMAND")
                    silent_run_with_timeout(post_mutant_cmd, post_mutant_timeout)
                if status_cmd != "":
                    restore_executable(executable, executable_code) # Might need for status
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
        if reachability_check_cmd != "":
            print ("FINAL COVERAGE ESTIMATE OVER", int(reachability_checks), "MUTANTS:",
                   str(round((reachability_hits / reachability_checks) * 100.0, 2)) + "%")
        if score:
            print ("FINAL MUTATION SCORE OVER", int(mutants_run), "MUTANTS:",
                    str(round((mutants_killed / mutants_run) * 100.0, 2)) + "%")
            print ("NOTE:  MUTANTS MAY BE REDUNDANT")
    finally:
        # always restore the original binary!
        restore_executable(executable, executable_code)

# Currently this is not used, and is not updated to match all changes to the API!
# It should work, but it does not support everything the command line does
def fuzz_with_mutants_via_function(fuzzer_fn, executable, budget,
                                   time_per_mutant, fraction_mutant,
                                   initial_fn=None, initial_budget=0,
                                   post_initial_fn=None,
                                   post_mutant_fn=None,
                                   status_fn=None, order=1):
    executable_code = mutate.get_code(executable)
    executable_jumps = mutate.get_jumps(executable)
    start_fuzz = time.time()
    mutant_no = 1
    try:
        if initial_fn is not None:
            print("=" * 10,
                  datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'),
                  "=" * 10)
            print("RUNNING INITIAL FUZZING...")
            try:
                with time_limit(initial_budget):
                    initial_fn()
            except TimeoutException:
                pass
            if status_fn is not None:
                print("INITIAL STATUS:")
                status_fn()
            if post_initial_fn is not None:
                post_initial_fn()

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
            try:
                with time_limit(time_per_mutant):
                    fuzzer_fn()
            except TimeoutException:
                pass
            print("FINISHED FUZZING IN", round(time.time() - start_run, 2), "SECONDS")
            if post_mutant_fn is not None:
                post_mutant_fn()
            if status_fn is not None:
                print("STATUS:")
                status_fn()

        print(datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))
        print(round(time.time() - start_fuzz, 2), "ELAPSED: STARTING FINAL FUZZ")
        restore_executable(executable, executable_code)
        try:
            with time_limit(int(budget - (time.time() - start_fuzz))):
                fuzzer_fn()
        except TimeoutException:
            pass
        print("COMPLETED ALL FUZZING AFTER", round(time.time() - start_fuzz, 2), "SECONDS")
        if status_fn is not None:
            print("FINAL STATUS:")
            status_fn()
    finally:
        # always restore the original binary!
        restore_executable(executable, executable_code)
