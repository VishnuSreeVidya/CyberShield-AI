import os
import sys
import time
import subprocess
import psycopg2

dsn = os.environ.get(
    'DATABASE_URL',
    'host=db port=5432 user=postgres password=postgres dbname=cybershield_ai'
)

print("[entrypoint] Waiting for PostgreSQL ...")
for i in range(30):
    try:
        conn = psycopg2.connect(dsn)
        conn.close()
        break
    except psycopg2.OperationalError:
        if i < 29:
            time.sleep(1)
        else:
            print("[entrypoint] PostgreSQL not ready. Exiting.")
            sys.exit(1)

print("[entrypoint] PostgreSQL is ready.")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ['FLASK_APP'] = 'run.py'

print("[entrypoint] Starting gunicorn ...")
os.execvp('gunicorn', [
    'gunicorn',
    '--bind', '0.0.0.0:5000',
    '--workers', '4',
    '--timeout', '120',
    '--access-logfile', '-',
    '--error-logfile', '-',
    'run:app',
])
