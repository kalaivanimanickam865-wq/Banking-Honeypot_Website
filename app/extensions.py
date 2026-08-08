from flask_sqlalchemy import SQLAlchemy

# Single shared SQLAlchemy instance, initialized against the app
# in the factory (app/__init__.py). Import this, not a new SQLAlchemy(),
# from anywhere else in the app to avoid duplicate DB bindings.
db = SQLAlchemy()
