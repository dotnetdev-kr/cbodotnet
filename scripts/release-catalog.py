#!/usr/bin/env python3
"""Build the public download catalog from complete, published GitHub releases."""
import argparse
from pathlib import Path

from release_catalog import main
from release_scorecard import publish


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--output-dir", type=Path)
    arguments, _ = parser.parse_known_args()
    main()
    if arguments.output_dir is None:
        raise ValueError("The completed Pages build must provide --output-dir")
    publish(arguments.output_dir)
