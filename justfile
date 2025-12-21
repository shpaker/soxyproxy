SOURCE_PATH := "soxy"
TESTS_PATH := "tests"

upgrade:
    uv lock --upgrade

fmt:
    uv run ruff format {{ SOURCE_PATH }}
    uv run ruff format {{ TESTS_PATH }}

lint:
    uv run ruff check {{ SOURCE_PATH }}

mypy:
    uv run python -m mypy --pretty {{ SOURCE_PATH }}

fix:
    uv run ruff check --fix --unsafe-fixes {{ SOURCE_PATH }}
#    uv run ruff check --fix --unsafe-fixes {{ TESTS_PATH }}

tests:
    uv run pytest -vvv tests/
