import argparse
from collections import namedtuple
import sys

import fuzzutil


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('fuzzer_cmd', type=str, default=None,
                        help='command to run fuzzer on executable')
    parser.add_argument('executable', metavar='filename', type=str, default=None,
                        help='executable to be fuzzer/mutated')
    parser.add_argument('--budget', type=int, default=3600,
                        help='total fuzzing budget (default 3600)')
    parser.add_argument('--time_per_mutant', type=int, default=300,
                        help='max time to fuzz each mutant (default 300)')
    parser.add_argument('--fraction_mutant', type=float, default=0.5,
                        help='portion of budget to devote to mutants (default 0.5)')
    parser.add_argument('--order', type=int, default=1,
                        help='mutation order (default 1)')
    parser.add_argument('--status_cmd', type=str, default="",
                        help='command to execute to show fuzzing stats')    

    parsed_args = parser.parse_args(sys.argv[1:])
    return (parsed_args, parser)


def make_config(pargs, parser):
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
    parsed_args, parser = parse_args()
    config = make_config(parsed_args, parser)
    fuzzutil.fuzz_with_mutants(config.fuzzer_cmd,
                               config.executable,
                               config.budget,
                               config.time_per_mutant,
                               config.fraction_mutant,
                               config.status_cmd,
                               config.order)



if __name__ == "__main__":
    main()
