import os

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()


def get_db():
    """
    Return a psycopg2 connection whose cursors return rows as dicts.
    The caller is responsible for closing the connection.
    """
    return psycopg2.connect(
        os.getenv("DATABASE_URL"),
        cursor_factory=psycopg2.extras.RealDictCursor,
    )
