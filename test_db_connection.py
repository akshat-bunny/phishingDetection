# test_db_connection.py

import pyodbc
import os

def get_db_connection():
    conn_str = (
        r'DRIVER={Microsoft Access Driver (*.mdb, *.accdb)};'
        r'DBQ=' + os.path.join(os.getcwd(), 'database', 'users.accdb') + ';'
    )
    return pyodbc.connect(conn_str)

def test_connection():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        rows = cursor.fetchall()
        print("Database connection successful. Users table contents:")
        for row in rows:
            print(row)
        conn.close()
    except Exception as e:
        print("Error connecting to the database:", e)

if __name__ == "__main__":
    test_connection()
