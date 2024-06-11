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


def silent_run_with_timeout(cmd, timeout, verbose):
    # Allow functions instead of commands, for use as a library from a script
    if verbose:
        print("*" * 30)
    if callable(cmd):
        try:
            if verbose:
                print("CALLING FUNCTION", cmd)
            with time_limit(timeout):
                return cmd()
        except TimeoutException:
            print("ABORTED WITH TIMEOUT")
            return 1 # non-zero return code may be interpreted as failure/crash/timeout
    dnull = open(os.devnull, 'w')
    if verbose:
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
        if verbose and len(cmd_errors_out) > 0:
            print("OUTPUT (TRUNCATED TO LAST 20 LINES):")
            print("\n".join(cmd_errors_out.split("\n")[-20:]))
    finally:
        if P.poll() is None:
            print("KILLING SUBPROCESS DUE TO TIMEOUT")
            os.killpg(os.getpgid(P.pid), signal.SIGTERM)
    if verbose:
        print("COMPLETE IN", round(time.time() - start_P, 2), "SECONDS")
        print("*" * 30)

    return P.returncode

# all _cmd arguments can also be Python functions
def fuzz_with_mutants(fuzzer_cmd, executable, budget, time_per_mutant, fraction_mutant,
                      only_mutate=[],
                      avoid_mutating=[],
                      only_mutate_file=None,
                      avoid_mutating_file=None,
                      reachability_check_cmd=None,
                      reachability_check_timeout=2.0,
                      unreach_cache_file=None,
                      no_unreach_cache=False,
                      prune_mutant_cmd=None,
                      prune_mutant_timeout=2.0,
                      initial_fuzz_cmd=None,
                      initial_budget=60,
                      post_initial_cmd=None,
                      post_mutant_cmd=None,
                      post_mutant_timeout=2.0,
                      status_cmd=None,
                      order=1,
                      score=False,
                      avoid_repeats=False,
                      repeat_retries=20,
                      save_mutants=None,
                      verbose=False,
                      skip_default_avoid=False,
                      mutate_standard_libraries=False):
    print("*" * 80)
    print("STARTING MUTTFUZZ WITH BUDGET", budget, "SECONDS")
    print()
    executable_code = mutate.get_code(executable)

    if initial_fuzz_cmd is None:
        initial_budget = 0

    if not skip_default_avoid:
        avoid_mutating.extend(["Fuzz", "fuzz",
                               "asan", "Asan", "ubsan", "Ubsan", "sanitizer",
                               "interceptor", "Interceptor", "interception", "Interception",
                               "StrstrCheck", "PosixSpawnImpl", "unpoison", "ClearShadowMemoryForContextStack", "wrapped_",
                               "CharCmpX", "CharCaseCmp", "write_iovec", "read_iovec", "real_clock_gettime", "write_hostent",
                               "write_msghdr", "read_msghdr", "FixRealStrtolEndptr", "StrtolFixAndCheck", "read_pollfd",
                               "write_pollfd", "write_mntent", "real_pthread_attr_getstack", "initialize_obstack",
                               "MlockIsUnsupported", "WrappedCookie", "RealStrLen", "WrappedFunopen", "PoisonAlignedStackMemory",
                               "PoisonMemory", "PoisonShadow", "FindBadAddress", "FixUnalignedStorage", "ShadowSegment",
                               "isDerivedFromAtOffset", "findBaseAtOffset",
                               "assert", "Assert",
                               "printf", "scanf", "memcpy", "memset", "memcmp",
                               "strncpy", "strcpy", "strnstr", "strstr", "strncmp", "strcmp",
                               "operator new", "operator delete", "register_tm_clones", "_init", "_cxx_global",
                               "_gnu_cxx", "dtors"])
    if only_mutate_file is not None:
        with open(only_mutate_file, 'r') as f:
            for function in f:
                only_mutate.append(function[:-1])
    if avoid_mutating_file is not None:
        with open(avoid_mutating_file, 'r') as f:
            for function in f:
                avoid_mutating.append(function[:-1])

    visited_mutants = {}
    unreach_cache = {}
    reach_cache = {} # Can only use effectively for order 1 mutants

    if score:
        if not avoid_repeats:
            print("WARNING: SCORE ESTIMATION WITHOUT --avoid_repeats WILL REPEAT SAMPLES")
        mutants_run = 0.0
        mutants_killed = 0.0
        fraction_mutant = 1.0 # No final fuzz for mutation score estimation!
        function_score = {}

    print("READ EXECUTABLE WITH", len(executable_code), "BYTES")
    (executable_jumps, function_map, function_reach) = mutate.get_jumps(executable, only_mutate,
                                                                        avoid_mutating, mutate_standard_libraries)
    print("FOUND", len(executable_jumps), "MUTABLE JUMPS IN", len(function_map), "FUNCTIONS")
    print("JUMPS BY FUNCTION:")
    if reachability_check_cmd is not None:
        function_coverage = {}
    for function in function_map:
        print(function, len(function_map[function]))
        if reachability_check_cmd is not None:
            function_coverage[function] = (0.0, 0.0)
        if score:
            function_score[function] = (0.0, 0.0)
    print()

    if unreach_cache_file is not None:
        if os.path.exists(unreach_cache_file):
            print("READING UNREACHABLE FUNCTION CACHE")
            with open(unreach_cache_file, 'r') as f:
                for line in f:
                    unreach_cache[line.split("\n")[0]] = True
            print("READ", len(unreach_cache), "UNREACHABLE FUNCTIONS")

    start_fuzz = time.time()
    mutant_no = 0
    try:
        if initial_fuzz_cmd is not None:
            print("=" * 10,
                  datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'),
                  "=" * 10)
            print("RUNNING INITIAL FUZZING...")
            silent_run_with_timeout(initial_fuzz_cmd, initial_budget, verbose)
            if status_cmd is not None:
                print("INITIAL STATUS:")
                subprocess.call(status_cmd, shell=True)
            if post_initial_cmd is not None:
                subprocess.call(post_initial_cmd, shell=True)

        if reachability_check_cmd is not None:
            func_reachability_filename = "/tmp/func_reachability_executable"
            reachability_filename = "/tmp/reachability_executable"
            reachability_checks = 0.0
            reachability_hits = 0.0
        else:
            func_reachability_filename = None
            reachability_filename = None
        while ((time.time() - start_fuzz) - initial_budget) < (budget * fraction_mutant):
            mutant_no += 1
            print()
            print()
            print()
            print("=" * 30,
                  datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'),
                  "=" * 30)
            print(round(time.time() - start_fuzz, 2),
                  "ELAPSED: GENERATING MUTANT #" + str(mutant_no))
            # make a new mutant of the executable; rename avoids hitting a busy executable
            (functions, locs) = mutate.mutate_from(executable_code, executable_jumps, function_reach, "/tmp/new_executable",
                                                   order=order, reachability_filename=reachability_filename,
                                                   func_reachability_filename=func_reachability_filename,
                                                   save_mutants=save_mutants, save_count=mutant_no,
                                                   avoid_repeats=avoid_repeats, repeat_retries=repeat_retries,
                                                   visited_mutants=visited_mutants, unreach_cache=unreach_cache)
            mutant_ok = True
            if reachability_check_cmd is not None:
                if verbose:
                    print()
                    print("=" * 40)
                    print("CHECKING REACHABILITY")
                reachability_checks += 1.0
                # First check the funciton itself is reachable                
                if tuple(functions) in reach_cache:
                    print("SKIPPING FUNCTION REACHABILITY, IN CACHE")
                    r = 1
                else:
                    os.rename(func_reachability_filename, executable)
                    subprocess.check_call(['chmod', '+x', executable])
                    r = silent_run_with_timeout(reachability_check_cmd, reachability_check_timeout, verbose)
                    restore_executable(executable, executable_code)
                if r == 0:
                    print("FUNCTION ITSELF IS NOT REACHABLE (RETURN CODE 0)")
                    mutant_ok = False
                    for function in functions:
                        if not no_unreach_cache:
                            unreach_cache[function] = True
                            if unreach_cache_file is not None:
                                with open(unreach_cache_file, 'a') as f:
                                    f.write(function + "\n")
                else:
                    reach_cache[tuple(functions)] = True
                    if tuple(locs) in reach_cache:
                        print("SKIPPING JUMP REACHABILITY,  IN CACHE")
                        r = 1
                    else:
                        os.rename(reachability_filename, executable)
                        subprocess.check_call(['chmod', '+x', executable])
                        r = silent_run_with_timeout(reachability_check_cmd, reachability_check_timeout, verbose)
                        restore_executable(executable, executable_code)
                    if r == 0:
                        print("MUTANT IS NOT REACHABLE (RETURN CODE 0)")
                        for loc in locs:
                            if not no_unreach_cache:
                                unreach_cache[loc] = True
                                # No file caching for location reachability
                        mutant_ok = False
                    else:
                        reach_cache[tuple(locs)] = True
                        reachability_hits += 1.0
                for function in functions:
                    (hits, total) = function_coverage[function]
                    if r == 0:
                        function_coverage[function] = (hits, total + 1)
                    else:
                        function_coverage[function] = (hits + 1, total + 1)
                    (hits, total) = function_coverage[function]
                    print(function + ":", str(round((hits / total) * 100.0, 2)) + "% COVERAGE")
                print ("RUNNING COVERAGE ESTIMATE OVER", int(reachability_checks), "MUTANTS:",
                       str(round((reachability_hits / reachability_checks) * 100.0, 2)) + "%")
            if mutant_ok:
                os.rename("/tmp/new_executable", executable)
                subprocess.check_call(['chmod', '+x', executable])
                if prune_mutant_cmd is not None:
                    if verbose:
                        print()
                        print("=" * 40)
                        print("PRUNING MUTANT...")
                    r = silent_run_with_timeout(prune_mutant_cmd, prune_mutant_timeout, verbose)
                    if r != 0:
                        print("PRUNING CHECK FAILED WITH RETURN CODE", r)
                        mutant_ok = False
            if mutant_ok:
                print()
                print("FUZZING/EVALUATING MUTANT...")
                start_run = time.time()
                r = silent_run_with_timeout(fuzzer_cmd, time_per_mutant, verbose)
                print("FINISHED IN", round(time.time() - start_run, 2), "SECONDS")
                if score:
                    print()
                    mutants_run += 1
                    if (r != 0):
                        mutants_killed += 1
                        print ("** MUTANT KILLED **")
                    else:
                        print ("** MUTANT NOT KILLED **")
                    for function in functions:
                        (kills, total) = function_score[function]
                        if r == 0:
                            function_score[function] = (kills, total + 1)
                        else:
                            function_score[function] = (kills + 1, total + 1)
                        (kills, total) = function_score[function]
                        print(function + ":", str(round((kills / total) * 100.0, 2)) + "% MUTATION SCORE")
                    print ("RUNNING MUTATION SCORE ON", int(mutants_run), "MUTANTS:",
                           str(round((mutants_killed / mutants_run) * 100.0, 2)) + "%")

                if post_mutant_cmd is not None:
                    restore_executable(executable, executable_code) # Might need original for post
                    print("RUNNING POST-MUTANT COMMAND")
                    silent_run_with_timeout(post_mutant_cmd, post_mutant_timeout, verbose)
                if status_cmd is not None:
                    restore_executable(executable, executable_code) # Might need for status
                    print("STATUS:")
                    subprocess.call(status_cmd, shell=True)

        print(datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))
        print(round(time.time() - start_fuzz, 2), "ELAPSED: STARTING FINAL FUZZ")
        restore_executable(executable, executable_code)
        silent_run_with_timeout(fuzzer_cmd, budget - (time.time() - start_fuzz), verbose)
        print("COMPLETED AFTER", round(time.time() - start_fuzz, 2), "SECONDS")
        if status_cmd is not None:
            print("FINAL STATUS:")
            subprocess.call(status_cmd, shell=True)

        if reachability_check_cmd is not None:
            print()
            for function in function_coverage:
                (hits, total) = function_coverage[function]
                if total > 0:
                    print(function + ":", str(round((hits / total) * 100.0, 2)) + "% COVERAGE (OUT OF",
                          str(int(total)) + ")")
                else:
                    print(function + ": NO COVERAGE CHECKS")
            print()

        if score:
            print()
            for function in function_score:
                (kills, total) = function_score[function]
                if total > 0:
                    print(function + ":", str(round((kills / total) * 100.0, 2)) + "% MUTATION SCORE (OUT OF",
                          str(int(total)) + ")")
                else:
                    if verbose:
                        print(function + ": NO MUTANTS EXECUTED")
            print()

        print()

        if reachability_check_cmd is not None:
            unreach_funcs = 0
            unreach_branches = 0
            for u in unreach_cache:
                if u in function_map:
                    print("** FUNCTION", u, "WITH", len(function_map[u]), "BRANCHES UNREACHABLE **")
                    unreach_funcs += 1
                    unreach_branches += len(function_map[u])
            print()
            print("TOTAL OF", unreach_funcs, "FUNCTIONS WITH", unreach_branches, "BRANCHES ARE UNREACHABLE")
            print()

        if reachability_check_cmd is not None:
            print("FINAL COVERAGE OVER", int(reachability_checks), "MUTANTS:",
                  str(round((reachability_hits / reachability_checks) * 100.0, 2)) + "%")
        if score:
            if mutants_run > 0:
                print("FINAL MUTATION SCORE OVER", int(mutants_run), "EXECUTED MUTANTS:",
                        str(round((mutants_killed / mutants_run) * 100.0, 2)) + "%")
            else:
                print("NO MUTANTS EXECUTED!")

        visits = visited_mutants.values()
        print("MAXIMUM VISITS TO A MUTANT:", max(visits))
        print("MEAN VISITS TO A MUTANT:", round(sum(visits) / (len(visits) * 1.0), 2))

    finally:
        # always restore the original binary!
        restore_executable(executable, executable_code)
