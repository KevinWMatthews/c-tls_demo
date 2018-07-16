#!/usr/bin/env python3

import argparse

def main():
    pass

if __name__ == '__main__':
    argument_parser = argparse.ArgumentParser(description='Generate TLS certificate chain')
    argument_parser.add_argument('command', help='Command to run')

    args = argument_parser.parse_args()
    main()
