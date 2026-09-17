from contextlib import contextmanager

from pymongo import MongoClient


@contextmanager
def transaction(client: MongoClient):
    with client.start_session() as session:
        with session.start_transaction():
            yield session
