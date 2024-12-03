SOURCE_PATH := "soxy"

upgrade:
    uv lock --upgrade

fmt:
    ruff format {{ SOURCE_PATH }}

lint:
    ruff check {{ SOURCE_PATH }}

mypy:
    python -m mypy --pretty {{ SOURCE_PATH }}

fix:
    ruff check --fix --unsafe-fixes {{ SOURCE_PATH }}

tests:
    pytest tests/
