import argparse
from collections import namedtuple
import sys

from muttfuzz import fuzzutil


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('base_executable', metavar='filename', type=str, default=None,
                        help='executable to be mutated')
    parser.add_argument('new_executable', metavar='filename', type=str, default=None,
                        help='new executable name')
    parser.add_argument('metadata_file', metavar='filename', type=str, default=None,
                        help='mutant metadata file to read and apply')

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
    fuzzutil.apply_mutant(config.base_executable,
                          config.new_executable,
                          config.metadata_file)



if __name__ == "__main__":
    main()
