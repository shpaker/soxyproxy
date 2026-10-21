SOURCE_PATH := "soxy"
TESTS_PATH := "tests"

upgrade:
    uv lock --upgrade

fmt:
    uv run ruff format {{ SOURCE_PATH }}
    uv run ruff format {{ TESTS_PATH }}

lint:
    uv run ruff check {{ SOURCE_PATH }}

typecheck:
    uv run ty check {{ SOURCE_PATH }}

fix:
    uv run ruff check --fix --unsafe-fixes {{ SOURCE_PATH }}
#    uv run ruff check --fix --unsafe-fixes {{ TESTS_PATH }}

tests:
    uv run pytest -vvv tests/

tests-ci:
    uv run pytest -vvv tests/ -m "not socks"
