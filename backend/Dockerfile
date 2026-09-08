# syntax=docker/dockerfile:1.7
FROM ghcr.io/astral-sh/uv:0.11.28@sha256:5c3ab83183a73c5d319a77009eb425b60d5bb937f339fb7876788ebf567baf48 AS uv

FROM python:3.13.14-slim-bookworm@sha256:de572b33eae61a53675a87bbd02b5e365df7b6b2b06c9276124e965cec08c452 AS builder
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app/backend
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/backend/.venv
COPY backend/pyproject.toml backend/uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project
COPY backend/src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev \
    && find /app/backend/.venv/lib/python3.13/site-packages -maxdepth 1 \
        \( -name 'cuda*' -o -name 'nvidia*' -o -name 'torch*' -o -name 'triton*' \) \
        -exec rm -rf {} +

FROM python:3.13.14-slim-bookworm@sha256:de572b33eae61a53675a87bbd02b5e365df7b6b2b06c9276124e965cec08c452 AS runtime
RUN groupadd --gid 10001 itda && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin itda
WORKDIR /app
COPY --from=builder /app/backend/.venv /app/backend/.venv
COPY backend/alembic.ini /app/backend/alembic.ini
COPY backend/migrations /app/backend/migrations
COPY backend/src /app/backend/src
COPY --chown=10001:10001 artifacts/public/catalog/mvp-scored-releases /app/artifacts/public/catalog/mvp-scored-releases
COPY --chown=10001:10001 artifacts/public/catalog/public-place-catalog-v1.json /app/artifacts/public/catalog/public-place-catalog-v1.json
COPY --chown=10001:10001 artifacts/public/catalog/public-evidence-inventory-v1.json /app/artifacts/public/catalog/public-evidence-inventory-v1.json
COPY --chown=10001:10001 artifacts/public/catalog/public-place-relations-v1.json /app/artifacts/public/catalog/public-place-relations-v1.json
RUN find /app/artifacts/public/catalog/mvp-scored-releases -type d -exec chmod 0555 {} + \
    && find /app/artifacts/public/catalog/mvp-scored-releases -type f -exec chmod 0444 {} + \
    && chmod 0444 /app/artifacts/public/catalog/public-place-catalog-v1.json \
        /app/artifacts/public/catalog/public-evidence-inventory-v1.json \
        /app/artifacts/public/catalog/public-place-relations-v1.json
ENV PATH=/app/backend/.venv/bin:$PATH \
    PYTHONPATH=/app/backend/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "itda.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips=*"]
