SOURCE_PATH := "soxy"

upgrade:
    uv lock --upgrade

fmt:
    ruff format {{ SOURCE_PATH }}
    ruff format ./tests

lint:
    ruff check {{ SOURCE_PATH }}

fix:
    ruff check --fix --unsafe-fixes {{ SOURCE_PATH }}
    ruff check --fix --unsafe-fixes ./tests

tests:
    pytest tests/
