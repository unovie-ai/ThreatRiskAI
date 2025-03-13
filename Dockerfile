FROM python:3.9-slim-buster

WORKDIR /app

COPY . /app

RUN set -x && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir python-dotenv==1.0.1 && \
    pip install --no-cache-dir Flask==3.0.2 && \
    pip install --no-cache-dir flasgger==0.9.4 && \
    pip install --no-cache-dir marshmallow==3.21.0 && \
    pip install --no-cache-dir werkzeug==3.0.1 && \
    pip install --no-cache-dir markupsafe==2.1.5

CMD ["/bin/bash", "-c", "while true; do sleep 1; done"]
