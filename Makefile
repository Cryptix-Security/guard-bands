.PHONY: install-dev test demo bench run

install-dev:
	python -m pip install -r requirements-dev.txt

test:
	python -m pytest

demo:
	python scripts/fastapi_demo.py

bench:
	python scripts/benchmark_parser.py

run:
	uvicorn app.main:app --reload
