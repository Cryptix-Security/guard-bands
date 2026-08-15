.PHONY: install-dev test build

PYTHON ?= python3

install-dev:
	$(PYTHON) -m pip install -r requirements-dev.txt

test:
	$(PYTHON) -m pytest

build:
	$(PYTHON) -m build
