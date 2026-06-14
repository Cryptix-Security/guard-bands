"""Legacy entry point for the converted pytest suite."""

import sys

import pytest


if __name__ == "__main__":
    raise SystemExit(pytest.main(sys.argv[1:] or ["tests"]))
