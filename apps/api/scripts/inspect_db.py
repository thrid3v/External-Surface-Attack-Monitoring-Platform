import os
from sqlalchemy import create_engine, inspect

url = os.environ.get('DATABASE_URL')
if not url:
    raise SystemExit('DATABASE_URL not set')

e = create_engine(url)
inspector = inspect(e)
if 'scans' not in inspector.get_table_names():
    print('scans table not found')
else:
    cols = inspector.get_columns('scans')
    print('columns in DB:')
    for c in cols:
        print('-', c['name'], type(c['type']).__name__)
