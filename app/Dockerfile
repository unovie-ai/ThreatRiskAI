FROM python:3.11-slim-buster

WORKDIR /app

COPY . /app

RUN set -x && \
    pip install --no-cache-dir --upgrade pip && \
    pip install -r requirements.txt && \
    llm install ${LLM_MODEL_INSTALL:-llm-gemini} && \
    llm install ${LLM_EMBED_INSTALL:-llm-embed-jina}

CMD ["python", "/app/app.py"]
