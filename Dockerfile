FROM python:3.14-alpine AS base-image
ARG VERSION
WORKDIR /service

# Install build dependencies
RUN apk add --no-cache --virtual .build-deps \
    gcc \
    musl-dev \
    libffi-dev \
    cargo \
    rust

# Install UV
RUN pip install --no-cache-dir uv

# Add project files
COPY pyproject.toml uv.lock README.md ./
COPY soxy ./soxy

# Install dependencies and build the project
RUN uv sync --no-dev && \
    uv build

# Create virtual environment and install the built package
RUN python -m venv .venv && \
    .venv/bin/pip install dist/*.whl

FROM python:3.14-alpine AS runtime-image
WORKDIR /service

# Copy virtual environment from the build stage
COPY --from=base-image /service/.venv ./.venv

# Set entrypoint
ENTRYPOINT ["/service/.venv/bin/soxy"]
