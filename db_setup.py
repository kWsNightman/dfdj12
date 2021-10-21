import sys
from sqlalchemy import Column, Integer
from sqlalchemy.dialects.postgresql import JSON

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from sqlalchemy import create_engine

Base = declarative_base()

DATABASE = {
    "ENGINE": "postgresql",
    "NAME": "django_db",
    "USER": "django",
    "PASSWORD": "123",
    "HOST": "localhost",
    "PORT": "5432"}
SQLALCHEMY_DATABASE_URI = '{ENGINE}://{USER}:{PASSWORD}@{HOST}/{NAME}'.format(**DATABASE)


class FormModel(Base):
    __tablename__ = 'dinamicform'

    id = Column(Integer, primary_key=True)
    data = Column(JSON)

    def __str__(self):
        return f'Json id: {str(self.id)}'


engine = create_engine(SQLALCHEMY_DATABASE_URI)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()
