from sqlalchemy import create_engine, inspect
from dotenv import load_dotenv
import os

load_dotenv()
database_url = os.getenv("DATABASE_URL")
if not database_url:
    raise ValueError("DATABASE_URL environment variable is not set")

engine = create_engine(database_url)
inspector = inspect(engine)

print("Existing tables:")
for table_name in inspector.get_table_names():
    print(f"- {table_name}")
    columns = inspector.get_columns(table_name)
    for column in columns:
        print(f"  * {column['name']}: {column['type']}") 