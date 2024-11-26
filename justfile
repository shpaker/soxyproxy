SOURCE_PATH := "soxyproxy"

upgrade:
    uv lock --upgrade

fmt:
    ruff format {{ SOURCE_PATH }}

lint:
    ruff check {{ SOURCE_PATH }}

fix:
    ruff check --fix --unsafe-fixes {{ SOURCE_PATH }}

tests:
    pytest tests/
