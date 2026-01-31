import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "mysql+mysqlconnector://root:password@localhost/marketplace"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
