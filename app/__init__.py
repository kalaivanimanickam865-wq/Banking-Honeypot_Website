import os

from flask import Flask

from .config import Config
from .extensions import db


def create_app(config_class=Config):
    """Application factory. Keeps app creation testable and lets
    seed_db.py / run.py / a future test suite build separate app
    instances without import-order side effects."""
    # templates/ and static/ live at the project root (sibling of this
    # app/ package), not inside app/ — Flask's default only looks inside
    # the package, so point it at the real locations explicitly.
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder=os.path.join(project_root, "templates"),
        static_folder=os.path.join(project_root, "static"),
    )
    app.config.from_object(config_class)

    # SQLite will not create its parent directory on its own — if
    # instance/ doesn't exist yet, db.create_all() fails with
    # "unable to open database file". Safe to call every startup.
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)

    from .routes import bp as main_bp
    app.register_blueprint(main_bp)

    return app
