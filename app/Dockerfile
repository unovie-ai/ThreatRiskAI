FROM python:3.11-slim-buster

WORKDIR /app

COPY . /app

RUN set -x && \
    pip install --no-cache-dir --upgrade pip && \
    pip install -r requirements.txt && \
    llm install ${LLM_MODEL_INSTALL:-llm-gemini} && \
    llm install ${LLM_EMBED_INSTALL:-llm-embed-jina}
# Create necessary directories
RUN mkdir -p /app/db /app/uploads

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
