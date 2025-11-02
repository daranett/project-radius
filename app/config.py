import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    DB_HOST = os.getenv('DB_HOST', 'freeradius-db')
    DB_NAME = os.getenv('DB_NAME', 'radius')
    DB_USER = os.getenv('DB_USER', 'radius')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'radiuspass')
    DB_PORT = os.getenv('DB_PORT', '5432')
