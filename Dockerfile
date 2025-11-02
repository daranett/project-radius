FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 5000

# Gunakan config file Gunicorn
CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
