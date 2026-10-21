FROM python:3.15-alpine AS base-image
ARG VERSION=0.0.0
COPY --from=ghcr.io/astral-sh/uv:0.13.4 /uv /bin/uv
ENV UV_PYTHON_DOWNLOADS=never
WORKDIR /service

# Add project files
COPY pyproject.toml README.md ./
COPY soxy ./soxy

# Build the package and install it into a virtual environment
RUN sed -i "s/0\.0\.0/${VERSION}/" pyproject.toml soxy/__init__.py && \
    uv build --wheel --out-dir dist && \
    uv venv .venv && \
    uv pip install --python .venv/bin/python --no-cache --compile-bytecode dist/*.whl

FROM python:3.15-alpine AS runtime-image
WORKDIR /service

# Copy virtual environment from the build stage
COPY --from=base-image /service/.venv ./.venv

# Set entrypoint
ENTRYPOINT ["/service/.venv/bin/soxy"]
