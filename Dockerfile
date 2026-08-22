FROM python:3.11-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src:/app \
    SENTINEL_UI_READONLY=1

COPY requirements.txt pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -r requirements.txt .

COPY app ./app
COPY artifacts ./artifacts
COPY datasets ./datasets
COPY configs ./configs

EXPOSE 8080
CMD ["sh", "-c", "uvicorn app.web.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
