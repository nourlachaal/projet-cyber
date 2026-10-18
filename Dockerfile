
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY honeypots ./honeypots
COPY backend ./backend

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "honeypots.http_hp.server"]
