import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'supersecretkey'
    DATABASE_CONFIG = {
        'host': 'localhost',
        'user': 'root',
        'password': '',
    }
