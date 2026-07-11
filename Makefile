.PHONY: install-dev test demo reference-demo dual-channel-demo bench run

install-dev:
	python -m pip install -r requirements-dev.txt

test:
	python -m pytest

demo:
	python scripts/fastapi_demo.py

reference-demo:
	python scripts/reference_app_demo.py

dual-channel-demo:
	python scripts/dual_channel_demo.py

bench:
	python scripts/benchmark_parser.py

run:
	uvicorn app.main:app --reload
