FROM python:3.12-slim

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent ./agent
COPY tests ./tests
COPY check_greenbone_ready.py ./check_greenbone_ready.py
COPY check_greenbone_feed_state.py ./check_greenbone_feed_state.py
ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "agent.main"]
