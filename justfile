SOURCE_PATH := "soxy"
TESTS_PATH := "tests"
IMAGE_NAME := "soxyproxy"
IMAGE_TAG := "latest"

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

tests-ci:
    uv run pytest -vvv tests/ -m "not socks"

build tag="latest" version="":
    #!/usr/bin/env bash
    if [ -n "{{ version }}" ]; then
        docker build --build-arg VERSION={{ version }} -t {{ IMAGE_NAME }}:{{ tag }} .
    else
        docker build -t {{ IMAGE_NAME }}:{{ tag }} .
    fi
