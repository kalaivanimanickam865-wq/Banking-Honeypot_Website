"""Entry point. Run with: python run.py
Reads HOST / PORT / DEBUG from env so it's configurable without
editing this file (Rule: expose behavior as flags, not hardcoded)."""
import os

from app import create_app
from app.extensions import db

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "true").lower() == "true"

    # use_reloader spawns a second ("worker") process that re-imports this
    # entire module, including the db.create_all() below. On Windows this
    # can race the first process for the SQLite file handle (AV/file-lock
    # timing) and raise "unable to open database file". Default it off;
    # flip FLASK_USE_RELOADER=true once you want autoreload-on-save and
    # aren't hitting that race. debug=True still gives you the in-browser
    # debugger either way.
    use_reloader = os.environ.get("FLASK_USE_RELOADER", "false").lower() == "true"

    if not use_reloader or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        os.makedirs(app.instance_path, exist_ok=True)
        with app.app_context():
            db.create_all()

    app.run(host=host, port=port, debug=debug, use_reloader=use_reloader)
