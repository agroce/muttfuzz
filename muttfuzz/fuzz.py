import argparse
from collections import namedtuple
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
                        help='string with comma delimited list of functions patterns to mutate (match by simple inclusion)')
    parser.add_argument('--avoid_mutating', type=str, default="",
                        help='string with comma delimited list of function patterns not to mutate (match by simple inclusion)')
    parser.add_argument('--reachability_check_cmd', type=str, default="",
                        help='command to check reachability; should return non-zero if some inputs crash')
    parser.add_argument('--reachability_check_timeout', type=float, default=2.0,
                        help='timeout for mutant check')
    parser.add_argument('--prune_mutant_cmd', type=str, default="",
                        help='command to check mutants for validity/interest')
    parser.add_argument('--prune_mutant_timeout', type=float, default=2.0,
                        help='timeout for mutant check')
    parser.add_argument('--initial_fuzz_cmd', type=str, default="",
                        help='command for initial fuzzing before mutants')
    parser.add_argument('--initial_budget', type=int, default=60,
                        help='how long to run initial fuzzing, in seconds (default 60)')
    parser.add_argument('--post_initial_cmd', type=str, default="",
                        help='command to run after initial fuzzing')
    parser.add_argument('--post_mutant_cmd', type=str, default="",
                        help='command to run after each mutant (e.g., fuzz of original)')
    parser.add_argument('--post_mutant_timeout', type=float, default=2.0,
                        help='timeout for post-mutant command')
    parser.add_argument('--status_cmd', type=str, default="",
                        help='command to execute to show fuzzing stats')
    parser.add_argument('--order', type=int, default=1,
                        help='mutation order (default 1)')
    parser.add_argument('-s', '--score', action='store_true',
                        help="compute a mutation score, instead of fuzzing.")
    parser.add_argument('--save_mutants', type=str, default="",
                        help='directory in which to save generated mutants/checks; no saving if not provided or empty')

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
    try:
        fuzzutil.fuzz_with_mutants(config.fuzzer_cmd,
                                   config.executable,
                                   config.budget,
                                   config.time_per_mutant,
                                   config.fraction_mutant,
                                   list(filter(None, config.only_mutate.replace(", ", ",").split(","))),
                                   list(filter(None, config.avoid_mutating.replace(", ", ",").split(","))),
                                   config.reachability_check_cmd,
                                   config.reachability_check_timeout,
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
                                   config.save_mutants)
    except IndexError:
        print("Target binary seems to have no jumps, so mutation will not do anything!")



if __name__ == "__main__":
    main()
