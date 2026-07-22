ARG PYTHON_IMAGE=python:3.12-alpine3.22@sha256:a190708a2dec1bd18b1decb539f8e8f5407abaa9bf39cacda583f7f8c11db322
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apk upgrade --no-cache \
    && addgroup -S -g 10001 agentsec \
    && adduser -S -D -H -u 10001 -G agentsec agentsec

COPY pyproject.toml README.md requirements.lock ./
COPY src ./src
COPY configs ./configs
COPY prompts ./prompts

RUN python -m pip install --no-cache-dir -r requirements.lock \
    && python -m pip install --no-cache-dir --no-deps .

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import json,urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3); assert r.status == 200; assert json.load(r)['status'] == 'ok'"

ENTRYPOINT ["agentsec"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
