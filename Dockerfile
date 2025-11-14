FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && \
    apt-get install -y --no-install-recommends postgresql-client && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY app/ .

EXPOSE 5000

# Gunakan config file Gunicorn
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
