FROM python:3.14-slim as base-image
ARG UV_VERSION=0.1.0
WORKDIR /service

# Install UV
RUN pip install "uv==$UV_VERSION"

# Add project files
ADD pyproject.toml poetry.lock readme.md ./
ADD _soxyproxy soxyproxy

# Install dependencies and build the project
RUN uv install --no-dev

# Create virtual environment and install the built package
RUN python -m venv .venv && \
    .venv/bin/pip install dist/*.whl

FROM python:3.14-alpine as runtime-image
WORKDIR /service

# Copy virtual environment from the build stage
COPY --from=base-image /service/.venv ./.venv

# Set entrypoint
ENTRYPOINT ["/service/.venv/bin/python", "-m", "soxyproxy"]
