from datetime import datetime, timezone
import glob
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager

from muttfuzz import mutate
from muttfuzz import live as live_mode
from muttfuzz import frontier as frontier_mode


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


def make_work_dir(executable):
    """Scratch directory for mutant/reachability/restore copies of the executable. It lives
    next to the executable because they are moved into place with os.rename, which fails
    across filesystems (e.g. /tmp vs. a Docker volume), and it is per-run, so several
    muttfuzz runs on one machine do not overwrite each other's files."""
    return tempfile.mkdtemp(prefix=".muttfuzz_", dir=os.path.dirname(os.path.abspath(executable)))


def restore_executable(executable, executable_code, work_dir=None):
    # We do this because it could still be busy if fuzzer hasn't shut down yet
    if work_dir is None:
        work_dir = os.path.dirname(os.path.abspath(executable))
    tmp = os.path.join(work_dir, ".muttfuzz_restore_executable")
    with open(tmp, 'wb') as f:
        f.write(executable_code)
    os.rename(tmp, executable)
    subprocess.check_call(['chmod', '+x', executable])


def kill_process_group(P, grace=10.0):
    """SIGTERM the process group led by Popen object P (started with setsid), wait up to
    `grace` seconds for every process in it to exit, then SIGKILL whatever is left.
    Returning only once the group is gone matters for fuzzers that lock their output
    directory (afl-fuzz flock()s it): starting the next run while the previous one is
    still shutting down makes the new one fail."""
    pgid = P.pid

    def group_alive():
        P.poll()  # reap our direct child, or it lingers as a zombie in the group
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False

    for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, 5.0)):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            break
        deadline = time.time() + wait
        while time.time() < deadline and group_alive():
            time.sleep(0.05)
        if not group_alive():
            break
    P.poll()


def silent_run_with_timeout(cmd, timeout, verbose, zero_timeout=False, kill_grace=10.0):
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
            if zero_timeout:
                return 0
            return 1 # non-zero return code may be interpreted as failure/crash/timeout
    dnull = open(os.devnull, 'w')
    if verbose:
        print("EXECUTING", cmd)
    start_P = time.time()
    timed_out = False
    P = None
    try:
        with open("cmd_errors.txt", 'w') as cmd_errors:
            P = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid,
                                 stdout=dnull, stderr=cmd_errors)
            while (P.poll() is None) and ((time.time() - start_P) < timeout):
                time.sleep(min(0.5, timeout / 10.0)) # Allow for small timeouts
            if P.poll() is None:
                print("KILLING SUBPROCESS DUE TO TIMEOUT")
                kill_process_group(P, kill_grace)
                timed_out = True
        with open("cmd_errors.txt", 'r') as cmd_errors:
            try:
                cmd_errors_out = cmd_errors.read()
            except: #pylint: disable=W0702
                cmd_errors_out = "ERROR READING OUTPUT"
        if verbose and len(cmd_errors_out) > 0:
            print("OUTPUT (TRUNCATED TO LAST 20 LINES):")
            print("\n".join(cmd_errors_out.split("\n")[-20:]))
    finally:
        if (P is not None) and (P.poll() is None):
            print("KILLING SUBPROCESS DUE TO TIMEOUT")
            kill_process_group(P, kill_grace)
            timed_out = True
    if verbose:
        if not timed_out:
            print("COMPLETED IN", round(time.time() - start_P, 2), "SECONDS")
        print("*" * 30)
    if timed_out and zero_timeout:
        return 0
    return P.returncode

def apply_mutant(base_executable, new_executable, metadata_file):
    executable_code = mutate.get_code(base_executable)
    (executable_jumps, _, function_reach) = mutate.get_jumps(base_executable)
    with open(metadata_file, "r") as f:
        metadata = f.read()
    mutate.apply_mutant_metadata(executable_code, executable_jumps, function_reach, metadata, new_executable)

# all _cmd arguments can also be Python functions
def fuzz_with_mutants(fuzzer_cmd, executable, budget, time_per_mutant, fraction_mutant,
                      only_mutate=None,
                      avoid_mutating=None,
                      only_mutate_file=None,
                      avoid_mutating_file=None,
                      source_only_mutate=None,
                      source_avoid_mutating=None,
                      source_only_mutate_file=None,
                      source_avoid_mutating_file=None,
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
                      repeat_retries=200,
                      stop_on_repeat=False,
                      no_timeout_kills=False,
                      save_mutants=None,
                      save_executables=False,
                      use_saved_mutants=None,
                      save_results=None,
                      verbose=False,
                      skip_default_avoid=False,
                      mutate_standard_libraries=False,
                      debug_info_only=False,
                      live=False,
                      kill_grace=10.0,
                      frontier_check=False,
                      frontier_probes=30,
                      progress_cmd=None,
                      max_time_per_mutant=None,
                      progress_window=None,
                      frontier_fraction=1.0):
    if live and score:
        raise ValueError("--live cannot be used with --score (mutation score needs one run per mutant)")
    if frontier_check and reachability_check_cmd is None:
        raise ValueError("--frontier_check needs --reachability_check_cmd (it runs the same corpus-replay command)")
    if not 0.0 <= frontier_fraction <= 1.0:
        raise ValueError("--frontier_fraction must be between 0 and 1")
    if only_mutate is None:
        only_mutate = []
    if avoid_mutating is None:
        avoid_mutating = []
    if source_only_mutate is None:
        source_only_mutate = []
    if source_avoid_mutating is None:
        source_avoid_mutating = []

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
    start_analyze = time.time()

    if only_mutate_file is not None:
        with open(only_mutate_file, 'r') as f:
            for function in f:
                only_mutate.append(function[:-1])
    if avoid_mutating_file is not None:
        with open(avoid_mutating_file, 'r') as f:
            for function in f:
                avoid_mutating.append(function[:-1])

    if source_only_mutate_file is not None:
        with open(source_only_mutate_file, 'r') as f:
            for source in f:
                source_only_mutate.append(source[:-1])
    if source_avoid_mutating_file is not None:
        with open(source_avoid_mutating_file, 'r') as f:
            for source in f:
                source_avoid_mutating.append(source[:-1])

    if use_saved_mutants is not None:
        metadatas = []
        for metadata_file in glob.glob(use_saved_mutants + "/*.metadata"):
            with open(metadata_file, "r") as f:
                metadatas.append(f.read())
        if len(metadatas) < 1:
            print("NO METADATA FILES FOUND!")
            sys.exit(1)
        random.shuffle(metadatas) # for avoid_repeats, just round robin

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
    sys.stdout.flush()
    (executable_jumps, function_map, function_reach) = mutate.get_jumps(executable, only_mutate, avoid_mutating,
                                                                        source_only_mutate, source_avoid_mutating,
                                                                        mutate_standard_libraries, debug_info_only)
    print("FOUND", len(executable_jumps), "MUTABLE JUMPS IN", len(function_map), "FUNCTIONS")
    no_line_info = len([j for j in executable_jumps.values() if j["source"] == ""])
    if (not debug_info_only) and (source_only_mutate == []) and \
       (0 < no_line_info < len(executable_jumps)) and (no_line_info > 0.25 * len(executable_jumps)):
        print("WARNING:", no_line_info, "OF THESE JUMPS ARE IN FUNCTIONS WITHOUT DEBUG INFO, WHILE OTHERS HAVE IT;")
        print("  in a binary built with -g these are usually sanitizer/fuzzer runtime code.")
        print("  Consider --debug_info_only or --source_only_mutate to mutate only the target's code.")
    print("JUMPS BY FUNCTION:")
    if reachability_check_cmd is not None:
        function_coverage = {}
    for function, function_jumps in function_map.items():
        print(function, len(function_jumps))
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

    print()
    print("INITIAL ANALYSIS OF EXECUTABLE TOOK", round(time.time() - start_analyze, 2), "SECONDS")

    work_dir = make_work_dir(executable)
    new_executable = os.path.join(work_dir, "new_executable")
    start_fuzz = time.time()
    mutant_no = 0
    analysis_data = []
    live_fuzzer = None
    patcher = None

    def live_wait(seconds, patches=None):
        """Let the live fuzzer run; False if it has exited. With patches, re-apply them about
        once a second, so processes the fuzzer (re)starts from the file on disk during the
        window (e.g. libFuzzer restarted by a wrapper after a crash) also run the mutant."""
        end = time.time() + seconds
        last_check = time.time()
        while time.time() < end:
            if live_fuzzer.poll() is not None:
                print("LIVE FUZZER EXITED WITH RETURN CODE", live_fuzzer.returncode)
                return False
            time.sleep(min(0.5, max(0.0, end - time.time())))
            if patches and time.time() - last_check >= 1.0:
                patcher.apply(patches, passes=1)
                last_check = time.time()
        return live_fuzzer.poll() is None

    def read_progress():
        """Last number printed by progress_cmd (e.g. a corpus size), or None."""
        try:
            out = subprocess.run(progress_cmd, shell=True, capture_output=True, text=True,
                                 timeout=30, check=False).stdout
        except (subprocess.SubprocessError, OSError):
            return None
        nums = re.findall(r"-?[0-9]+(?:[.][0-9]+)?", out)
        return float(nums[-1]) if nums else None

    def adaptive_run(wait_fn, phase_end):
        """Adaptive dwell time: run the mutant for at least time_per_mutant, then keep extending
        it one progress window at a time while the progress command reported an increase during
        the last window, up to max_time_per_mutant and the end of the mutant phase.
        wait_fn(seconds) runs the fuzzer for that long, returning False if it exited.
        Returns False if the fuzzer exited."""
        window = progress_window if progress_window is not None else time_per_mutant
        max_t = max_time_per_mutant if max_time_per_mutant is not None else 4 * time_per_mutant
        start = time.time()
        last = read_progress()
        progressed = False
        while time.time() - start < time_per_mutant:
            if not wait_fn(min(window, time_per_mutant - (time.time() - start))):
                return False
            now = read_progress()
            progressed = (now is not None) and (last is not None) and (now > last)
            last = now
        while progressed:
            remaining = min(max_t - (time.time() - start), phase_end - time.time())
            if remaining <= 1:
                print("MUTANT REACHED ITS TIME LIMIT WHILE STILL MAKING PROGRESS")
                break
            print("EXTENDING MUTANT: PROGRESS", last, "IN LAST WINDOW")
            if not wait_fn(min(window, remaining)):
                return False
            now = read_progress()
            progressed = (now is not None) and (last is not None) and (now > last)
            last = now
        print("MUTANT RAN FOR", round(time.time() - start, 2), "SECONDS")
        return True

    def process_wait(P):
        def wait_fn(seconds):
            end = time.time() + seconds
            while time.time() < end:
                if P.poll() is not None:
                    return False
                time.sleep(min(0.5, max(0.0, end - time.time())))
            return P.poll() is None
        return wait_fn

    reachability_checks = 0.0
    reachability_hits = 0.0
    frontier_finder = None
    if frontier_check:
        frontier_finder = frontier_mode.FrontierFinder(
            executable_code, executable_jumps, function_reach, executable, work_dir,
            lambda: silent_run_with_timeout(reachability_check_cmd, reachability_check_timeout, verbose),
            unreach_cache=unreach_cache)

    try:
        if live:
            # one fuzzer run for the whole budget; mutants are applied to its processes
            live_cmd = initial_fuzz_cmd if initial_fuzz_cmd is not None else fuzzer_cmd
            print("=" * 10,
                  datetime.fromtimestamp(time.time(), timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                  "=" * 10)
            print("STARTING LIVE FUZZER (MUTANTS WILL BE SWITCHED IN PLACE):", live_cmd)
            with open("cmd_errors_live.txt", 'w') as live_errors:
                live_fuzzer = subprocess.Popen(live_cmd, shell=True, preexec_fn=os.setsid,
                                               stdout=subprocess.DEVNULL, stderr=live_errors)
            patcher = live_mode.LivePatcher(executable, live_fuzzer.pid, verbose)
            print("RUNNING INITIAL FUZZING...")
            live_wait(initial_budget)
            if status_cmd is not None:
                print("INITIAL STATUS:")
                subprocess.call(status_cmd, shell=True)
            if post_initial_cmd is not None:
                subprocess.call(post_initial_cmd, shell=True)
        elif initial_fuzz_cmd is not None:
            print("=" * 10,
                  datetime.fromtimestamp(time.time(), timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                  "=" * 10)
            print("RUNNING INITIAL FUZZING...")
            silent_run_with_timeout(initial_fuzz_cmd, initial_budget, verbose)
            if status_cmd is not None:
                print("INITIAL STATUS:")
                subprocess.call(status_cmd, shell=True)
            if post_initial_cmd is not None:
                subprocess.call(post_initial_cmd, shell=True)

        if reachability_check_cmd is not None:
            func_reachability_filename = os.path.join(work_dir, "func_reachability_executable")
            reachability_filename = os.path.join(work_dir, "reachability_executable")
            reachability_checks = 0.0
            reachability_hits = 0.0
            # Sanity check: on the unmutated executable the check should pass (return 0). If it
            # does not (e.g. the corpus contains an input that crashes the real program, or the
            # check times out), every mutant will look reachable and nothing is pruned.
            r = silent_run_with_timeout(reachability_check_cmd, reachability_check_timeout, verbose)
            if r != 0:
                print("WARNING: REACHABILITY CHECK FAILS (RETURN CODE " + str(r) + ") ON THE UNMUTATED EXECUTABLE;")
                print("  every mutant will look reachable. Check for corpus inputs that crash or hang the")
                print("  original program, or a --reachability_check_timeout that is too short.")
        else:
            func_reachability_filename = None
            reachability_filename = None
        while ((time.time() - start_fuzz) - initial_budget) < (budget * fraction_mutant):
            sys.stdout.flush() # Let's see output more regularly

            mutant_no += 1
            print()
            print()
            print()
            print("=" * 30,
                  datetime.fromtimestamp(time.time(), timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                  "=" * 30)
            frontier_pick = None
            if (use_saved_mutants is None) and (frontier_finder is not None):
                print(round(time.time() - start_fuzz, 2), "ELAPSED: GENERATING MUTANT #" + str(mutant_no))
                probes_before = frontier_finder.probes_run
                if random.random() >= frontier_fraction:
                    # --frontier_fraction: some mutants skip the frontier search and flip any
                    # reachable jump (both sides covered, say), which may still change data
                    print("NOT SEARCHING THE FRONTIER (--frontier_fraction", str(frontier_fraction) +
                          "); USING A RANDOM REACHABLE MUTANT")
                else:
                    frontier_pick = frontier_finder.find(mutant_no, frontier_probes)
                    if frontier_pick is None:
                        print("NO FRONTIER JUMP FOUND IN", frontier_finder.probes_run - probes_before,
                              "PROBES; USING A RANDOM REACHABLE MUTANT")
                if frontier_pick is not None:
                    (loc, status) = frontier_pick
                    jump = executable_jumps[loc]
                    new_data = frontier_finder.mutant(loc, status)
                    print("FRONTIER JUMP (" + str(frontier_finder.probes_run - probes_before), "PROBES): THE CORPUS",
                          "NEVER TAKES" if status == "not_taken" else "ALWAYS TAKES", "THIS JUMP")
                    print("MUTATING JUMP IN", jump["function_name"], "WITH ORIGINAL OPCODE", jump["opcode"])
                    print("ORIGINAL CODE:", jump["code"])
                    print("AT LINE:", jump["source"])
                    print("CHANGING TO", "jmp" if status == "not_taken" else "NOPS")
                    new_code = bytearray(executable_code)
                    new_code[loc:loc + len(new_data)] = new_data
                    function = jump["function_name"]
                    meta = function + "\n" + str(loc - function_reach[function]) + "\n" + str(len(new_data)) + "\n"
                    meta += "".join(str(int(b)) + "\n" for b in new_data)
                    mutate.write_files(new_code, meta, None, None, new_executable, save_mutants=save_mutants,
                                       save_executables=save_executables, save_count=mutant_no)
                    functions, locs = [function], [loc]
                    visited_mutants[(loc, new_data)] = visited_mutants.get((loc, new_data), 0) + 1
            if (use_saved_mutants is None) and (frontier_pick is None):
                if frontier_finder is None:
                    print(round(time.time() - start_fuzz, 2), "ELAPSED: GENERATING MUTANT #" + str(mutant_no))
                # make a new mutant of the executable; rename avoids hitting a busy executable
                try:
                    (functions, locs, meta) = mutate.mutate_from(executable_code, executable_jumps, function_reach, new_executable,
                                                                 order=order, reachability_filename=reachability_filename,
                                                                 func_reachability_filename=func_reachability_filename,
                                                                 save_mutants=save_mutants, save_executables=save_executables, save_count=mutant_no,
                                                                 avoid_repeats=avoid_repeats, repeat_retries=repeat_retries,
                                                                 visited_mutants=visited_mutants, unreach_cache=unreach_cache)
                except (RuntimeError, IndexError) as e:
                    # every jump is known unreachable (or there are none): stop the mutant
                    # phase rather than crash and lose the rest of the budget
                    print("NO MUTANT CAN BE GENERATED (" + str(e) + "); ENDING MUTANT PHASE")
                    break
                if stop_on_repeat and max(visited_mutants.values()) > 1:
                    print("FORCED TO REPEAT A MUTANT, STOPPING ANALYSIS")
                    if save_mutants is not None:
                        # Don't keep repeated mutants
                        subprocess.call("rm " + save_mutants + "/*_" + str(mutant_no) + ".*", shell=True)
                    break
            elif use_saved_mutants is not None:
                print(round(time.time() - start_fuzz, 2), "ELAPSED: APPLYING MUTANT #" + str(mutant_no))
                if stop_on_repeat and ((mutant_no - 1) >= len(metadatas)):
                    print("FORCED TO REPEAT A MUTANT, STOPPING ANALYSIS")
                    break
                if avoid_repeats:
                    metadata = metadatas[(mutant_no - 1) % len(metadatas)]
                else:
                    metadata = random.choice(metadatas)
                (functions, locs, meta) = mutate.apply_mutant_metadata(executable_code, executable_jumps, function_reach, metadata, new_executable,
                                                                       visited_mutants)
            mutant_ok = True
            if not functions and not locs: # Can only happen if apply fails
                mutant_ok = False
            mutant_name = meta.replace("\n", "::")
            if (reachability_check_cmd is not None) and (frontier_pick is None):
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
                    restore_executable(executable, executable_code, work_dir)
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
                        restore_executable(executable, executable_code, work_dir)
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
                if live:
                    with open(new_executable, 'rb') as f:
                        live_patches = live_mode.diff(executable_code, f.read())
                if (not live) or (prune_mutant_cmd is not None):
                    # (in live mode the file on disk stays the original except for pruning, so
                    # processes the fuzzer starts meanwhile never pick up a stale mutant)
                    os.rename(new_executable, executable)
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
            if live:
                # the running fuzzer gets the mutant in memory; keep the original on disk
                restore_executable(executable, executable_code, work_dir)
            if (save_mutants is not None) and (not mutant_ok):
                # Don't keep unreachable mutants
                subprocess.call("rm " + save_mutants + "/*_" + str(mutant_no) + ".*", shell=True)
            if mutant_ok:
                print()
                print("FUZZING/EVALUATING MUTANT...")
                sys.stdout.flush()
                start_run = time.time()
                if live:
                    n_procs = 0
                    give_up = time.time() + 10.0  # the fuzzer may still be starting up
                    while n_procs == 0 and live_fuzzer.poll() is None and time.time() < give_up:
                        n_procs = patcher.apply(live_patches)
                        if n_procs == 0:
                            time.sleep(0.2)
                    if n_procs == 0:
                        print("LIVE FUZZER IS NOT RUNNING THE EXECUTABLE; ENDING MUTANT PHASE")
                        break
                    print("SWITCHED", len(live_patches), "PATCHED LOCATION(S) INTO", n_procs, "LIVE PROCESS(ES)")
                    if progress_cmd is not None:
                        phase_end = start_fuzz + initial_budget + budget * fraction_mutant
                        still_running = adaptive_run(lambda t: live_wait(t, live_patches), phase_end)
                    else:
                        still_running = live_wait(time_per_mutant, live_patches)
                    patcher.apply(live_mode.inverse(executable_code, live_patches))
                    r = 0
                    if not still_running:
                        break
                elif (progress_cmd is not None) and (not score):
                    phase_end = start_fuzz + initial_budget + budget * fraction_mutant
                    with open("cmd_errors.txt", 'w') as cmd_errors:
                        P = subprocess.Popen(fuzzer_cmd, shell=True, preexec_fn=os.setsid,
                                             stdout=subprocess.DEVNULL, stderr=cmd_errors)
                    try:
                        adaptive_run(process_wait(P), phase_end)
                    finally:
                        if P.poll() is None:
                            kill_process_group(P, kill_grace)
                    r = 0
                else:
                    r = silent_run_with_timeout(fuzzer_cmd, time_per_mutant, verbose, zero_timeout=no_timeout_kills)
                print("FINISHED IN", round(time.time() - start_run, 2), "SECONDS")
                analysis_data.append((mutant_name, round(time.time() - start_run, 2), r))
                if score:
                    print()
                    mutants_run += 1
                    if r != 0:
                        mutants_killed += 1
                        if save_mutants is not None:
                            if save_executables:
                                os.rename(save_mutants + "/mutant_" + str(mutant_no) + ".exe", save_mutants + "/killed_" + str(mutant_no) + ".exe")
                            os.rename(save_mutants + "/mutant_" + str(mutant_no) + ".metadata", save_mutants + "/killed_" + str(mutant_no) + ".metadata")
                        print ("** MUTANT KILLED **")
                    else:
                        print ("** MUTANT NOT KILLED **")
                        if save_mutants is not None:
                            if save_executables:
                                os.rename(save_mutants + "/mutant_" + str(mutant_no) + ".exe", save_mutants + "/survived_" + str(mutant_no) + ".exe")
                            os.rename(save_mutants + "/mutant_" + str(mutant_no) + ".metadata", save_mutants + "/survived_" + str(mutant_no) + ".metadata")
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
                analysis_times = list(map(lambda x:x[1], analysis_data))
                print("RUNNING MEAN TIME FOR MUTANT EVALUATION:", round(sum(analysis_times) / len(analysis_times), 2), "SECONDS")

                if post_mutant_cmd is not None:
                    restore_executable(executable, executable_code, work_dir) # Might need original for post
                    print("RUNNING POST-MUTANT COMMAND")
                    silent_run_with_timeout(post_mutant_cmd, post_mutant_timeout, verbose)
                if status_cmd is not None:
                    restore_executable(executable, executable_code, work_dir) # Might need for status
                    print("STATUS:")
                    subprocess.call(status_cmd, shell=True)

        if (not score) and (fraction_mutant < 1.0 or live):
            print(datetime.fromtimestamp(time.time(), timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
            print(round(time.time() - start_fuzz, 2), "ELAPSED: STARTING FINAL FUZZ")
            restore_executable(executable, executable_code, work_dir)
            if live:
                if live_fuzzer.poll() is None:
                    live_wait(budget - (time.time() - start_fuzz))
            else:
                silent_run_with_timeout(fuzzer_cmd, budget - (time.time() - start_fuzz), verbose)
            print("COMPLETED AFTER", round(time.time() - start_fuzz, 2), "SECONDS")
            if status_cmd is not None:
                print("FINAL STATUS:")
                subprocess.call(status_cmd, shell=True)

        if reachability_check_cmd is not None:
            print()
            for function, (hits, total) in function_coverage.items():
                if total > 0:
                    print(function + ":", str(round((hits / total) * 100.0, 2)) + "% COVERAGE (OUT OF",
                          str(int(total)) + ")")
                else:
                    print(function + ": NO COVERAGE CHECKS")
            print()

        if score:
            print()
            for function, (kills, total) in function_score.items():
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

        if frontier_finder is not None:
            print("FRONTIER PROBES RUN:", frontier_finder.probes_run)
        if (reachability_check_cmd is not None) and (reachability_checks > 0):
            print("FINAL COVERAGE OVER", int(reachability_checks), "MUTANTS:",
                  str(round((reachability_hits / reachability_checks) * 100.0, 2)) + "%")
        if score:
            if mutants_run > 0:
                print("FINAL MUTATION SCORE OVER", int(mutants_run), "EXECUTED MUTANTS:",
                        str(round((mutants_killed / mutants_run) * 100.0, 2)) + "%")
            else:
                print("NO MUTANTS EXECUTED!")

        visits = visited_mutants.values()
        if visits:
            print("MAXIMUM VISITS TO A MUTANT:", max(visits))
            print("MEAN VISITS TO A MUTANT:", round(sum(visits) / (len(visits) * 1.0), 2))
        analysis_times = list(map(lambda x:x[1], analysis_data))
        if analysis_times:
            print("MEAN TIME FOR MUTANT EVALUATION:", round(sum(analysis_times) / len(analysis_times), 2), "SECONDS")
        if save_results is not None:
            with open(save_results, 'w') as f:
                for d in analysis_data:
                    f.write('"' + d[0] + '",' + str(d[1]) + "," + str(d[2]) + "\n")

    finally:
        if live_fuzzer is not None and live_fuzzer.poll() is None:
            kill_process_group(live_fuzzer, kill_grace)
        # always restore the original binary!
        restore_executable(executable, executable_code, work_dir)
        shutil.rmtree(work_dir, ignore_errors=True)
