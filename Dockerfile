FROM python:3.9-slim-buster

WORKDIR /app

COPY . /app

RUN set -x && \
    pip install --no-cache-dir --upgrade pip && \
    pip install -r requirements.txt && \
+   llm install llm-gemini && \
+   llm install llm-embed-jina

CMD ["python", "/app/app.py"]
