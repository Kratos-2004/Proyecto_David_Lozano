import mysql.connector
from config import Config

def conectar_db(database):
    config = Config.DATABASE_CONFIG
    config['database'] = database
    return mysql.connector.connect(**config)

def obtener_cursor(db_connection):
    return db_connection.cursor()
