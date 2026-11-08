#!/usr/bin/env python3
"""Dispatch reviewed native musl SDK expansion routes without changing SDK10."""
import importlib.util
from pathlib import Path


def main():
    # Additional versions need a separately reviewed producer, not a repack fallback.
    path = Path(__file__).with_name('musl-modern-sdk.py')
    spec = importlib.util.spec_from_file_location('expanded_native_musl_sdk', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main()


if __name__ == '__main__':
    main()
