FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATABASE_PATH=/app/data/santa.db
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY santa_bot ./santa_bot
VOLUME ["/app/data"]
CMD ["python", "-m", "santa_bot"]
