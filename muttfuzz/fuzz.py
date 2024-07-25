import argparse
from collections import namedtuple
import random
import sys

from muttfuzz import fuzzutil


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('fuzzer_cmd', type=str, default=None,
                        help='command to run fuzzer on executable')
    parser.add_argument('executable', metavar='filename', type=str, default=None,
                        help='executable to be fuzzer/mutated')
    parser.add_argument('--budget', type=int, default=3600,
                        help='total fuzzing budget in seconds (default 3600)')
    parser.add_argument('--time_per_mutant', type=int, default=300,
                        help='max time to fuzz each mutant in seconds (default 300)')
    parser.add_argument('--fraction_mutant', type=float, default=0.5,
                        help='portion of budget to devote to mutants (default 0.5)')
    parser.add_argument('--only_mutate', type=str, default="",
                        help='string with comma delimited list of function patterns to mutate (match by inclusion)')
    parser.add_argument('--avoid_mutating', type=str, default="",
                        help='string with comma delimited list of function patterns NOT to mutate (match by simple inclusion)')
    parser.add_argument('--only_mutate_file', metavar='filename', type=str, default=None,
                        help='file with a list of functions (one per line) that are to be mutated')
    parser.add_argument('--avoid_mutating_file', metavar='filename', type=str, default=None,
                        help='file with a list of functions not to mutate')
    parser.add_argument('--source_only_mutate', type=str, default="",
                        help='string with comma delimited list of patterns to check for in source location')
    parser.add_argument('--source_avoid_mutating', type=str, default="",
                        help='string with comma delimited list of patterns to check (and avoid) in source location')
    parser.add_argument('--source_only_mutate_file', metavar='filename', type=str, default=None,
                        help='file with a list of source file patterns (one per line) that are to be mutated')
    parser.add_argument('--source_avoid_mutating_file', metavar='filename', type=str, default=None,
                        help='file with a list of source file patterns not to mutate')
    parser.add_argument('--reachability_check_cmd', type=str, default=None,
                        help='command to check reachability; should return non-zero if some inputs crash')
    parser.add_argument('--reachability_check_timeout', type=float, default=2.0,
                        help='timeout for mutant check')
    parser.add_argument('--unreach_cache_file', metavar='filename', type=str, default=None,
                        help='file for unreachability cache, created if does not exist, otherwise read')
    parser.add_argument('--no_unreach_cache', action='store_true',
                        help='do not make use of the unreachability cache (sometimes useful for fuzzing)')
    parser.add_argument('--prune_mutant_cmd', type=str, default=None,
                        help='command to check mutants for validity/interest')
    parser.add_argument('--prune_mutant_timeout', type=float, default=2.0,
                        help='timeout for mutant check')
    parser.add_argument('--initial_fuzz_cmd', type=str, default=None,
                        help='command for initial fuzzing before mutants')
    parser.add_argument('--initial_budget', type=int, default=60,
                        help='how long to run initial fuzzing, in seconds (default 60)')
    parser.add_argument('--post_initial_cmd', type=str, default=None,
                        help='command to run after initial fuzzing')
    parser.add_argument('--post_mutant_cmd', type=str, default=None,
                        help='command to run after each mutant (e.g., fuzz of original)')
    parser.add_argument('--post_mutant_timeout', type=float, default=2.0,
                        help='timeout for post-mutant command')
    parser.add_argument('--status_cmd', type=str, default=None,
                        help='command to execute to show fuzzing stats')
    parser.add_argument('--order', type=int, default=1,
                        help='mutation order (default 1)')
    parser.add_argument('-s', '--score', action='store_true',
                        help='compute a mutation score, instead of fuzzing')
    parser.add_argument('--avoid_repeats', action='store_true',
                        help='avoid using the same mutant multiple times, if possible')
    parser.add_argument('--repeat_retries', type=int, default=200,
                        help='number of times to retry to avoid a repeat mutant (default 200)')
    parser.add_argument('--stop_on_repeat', action='store_true',
                        help='Terminate analysis if a mutant has to be repeated')
    parser.add_argument('--save_mutants', type=str, default=None,
                        help='directory in which to save generated mutants/checks; no saving if not provided or empty')
    parser.add_argument('--save_executables', action='store_true',
                        help='Save full executables, not just metadata')
    parser.add_argument('--use_saved_mutants', type=str, default=None,
                        help='instead of generating mutants, apply mutants in metadata format in given directory')
    parser.add_argument('--save_results', type=str, default=None,
                        help='filename in which to save comma delimited mutation analysis results')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='more verbose fuzzing, with command outputs')
    parser.add_argument('--skip_default_avoid', action='store_true',
                        help='do not use the default list of function to skip (e.g. printf)')
    parser.add_argument('--mutate_standard_libraries', action='store_true',
                        help='allow mutation of C++ standard library and boost functions')
    parser.add_argument('--seed', type=int, default=None,
                        help='seed for random generation (default None)')

    parsed_args = parser.parse_args(sys.argv[1:])
    return (parsed_args, parser)


def make_config(pargs):
    """
    Process the raw arguments, returning a namedtuple object holding the
    entire configuration, if everything parses correctly.
    """
    pdict = pargs.__dict__
    # create a namedtuple object for fast attribute lookup
    key_list = list(pdict.keys())
    arg_list = [pdict[k] for k in key_list]
    Config = namedtuple('Config', key_list)
    nt_config = Config(*arg_list)
    return nt_config

def main():
    parsed_args, _ = parse_args()
    config = make_config(parsed_args)
    if config.seed is not None:
        random.seed(config.seed)
    fuzzutil.fuzz_with_mutants(config.fuzzer_cmd,
                               config.executable,
                               config.budget,
                               config.time_per_mutant,
                               config.fraction_mutant,
                               list(filter(None, config.only_mutate.replace(", ", ",").split(","))),
                               list(filter(None, config.avoid_mutating.replace(", ", ",").split(","))),
                               config.only_mutate_file,
                               config.avoid_mutating_file,
                               list(filter(None, config.source_only_mutate.replace(", ", ",").split(","))),
                               list(filter(None, config.source_avoid_mutating.replace(", ", ",").split(","))),
                               config.source_only_mutate_file,
                               config.source_avoid_mutating_file,
                               config.reachability_check_cmd,
                               config.reachability_check_timeout,
                               config.unreach_cache_file,
                               config.no_unreach_cache,
                               config.prune_mutant_cmd,
                               config.prune_mutant_timeout,
                               config.initial_fuzz_cmd,
                               config.initial_budget,
                               config.post_initial_cmd,
                               config.post_mutant_cmd,
                               config.post_mutant_timeout,
                               config.status_cmd,
                               config.order,
                               config.score,
                               config.avoid_repeats,
                               config.repeat_retries,
                               config.stop_on_repeat,
                               config.save_mutants,
                               config.save_executables,
                               config.use_saved_mutants,
                               config.save_results,
                               config.verbose,
                               config.skip_default_avoid,
                               config.mutate_standard_libraries)



if __name__ == "__main__":
    main()
