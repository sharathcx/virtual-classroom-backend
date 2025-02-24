from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

DATABASE_URL = ("mysql+mysqlconnector://"
                "mysql:ljMo4YBkldtx6UvY9XcpGbbw5W6cdadhg4gOAEs9OUdAabOMehwHEjHGUptvmhyO"
                "@49.12.198.14:5432/virtualclassroom")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()