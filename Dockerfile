FROM python:3.14.6-slim-bookworm@sha256:4ff4b92a68355dbdb52584ab3391dff8d371a61d4e063468bfd0130e3189c6d9 AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
WORKDIR /app
RUN python -m pip install uv==0.11.28
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
COPY fixtures ./fixtures
COPY web ./web
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.14.6-slim-bookworm@sha256:4ff4b92a68355dbdb52584ab3391dff8d371a61d4e063468bfd0130e3189c6d9

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CLEAN_ROOM_DATA_DIR=/data
WORKDIR /app
RUN groupadd --gid 10001 cleanroom \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin cleanroom \
    && mkdir /data \
    && chown 10001:10001 /data
COPY --from=build --chown=10001:10001 /app/.venv /app/.venv
COPY --chown=10001:10001 fixtures ./fixtures
COPY --chown=10001:10001 web ./web
COPY --chown=10001:10001 README.md LICENSE ./
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]
ENTRYPOINT ["clean-room"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
