# Gunicorn configuration file
bind = "0.0.0.0:5000"
workers = 1
worker_class = "sync"
timeout = 120
max_requests = 1000
max_requests_jitter = 50
preload_app = True

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"
