import os

basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


class Config:
    """Central config, driven by environment variables.

    All values have safe local-dev defaults so `python run.py` works
    out of the box, but SECRET_KEY and DATABASE_URL should be set via
    .env (see .env.example) for anything beyond your own machine.
    """

    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-this-key")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(basedir, "instance", "honeypot.db"),
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes, in seconds

    # Flags below are read by routes.py — expose behavior as config,
    # not hardcoded values, so grading/demo runs can be adjusted
    # without touching route logic.
    LOG_SUCCESSFUL_LOGINS = os.environ.get("LOG_SUCCESSFUL_LOGINS", "true").lower() == "true"
    MAX_LOGGED_PASSWORD_LENGTH = int(os.environ.get("MAX_LOGGED_PASSWORD_LENGTH", "255"))
