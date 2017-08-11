#!/usr/bin/env python3

import argparse
import os

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Copy congdb kernel files to the given kernel folder.'
    )
    parser.add_argument('path', type=str, help='path to copy files')
    args = parser.parse_args()

    # TODO: for each dir in root copy to the destination
    os.system("cp -r include {}".format(args.path))
    os.system("cp -r net {}".format(args.path))
