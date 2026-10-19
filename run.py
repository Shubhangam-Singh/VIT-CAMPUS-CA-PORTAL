"""Start the VIT Campus CA Portal on http://localhost:5000

    python run.py                  normal start
    FLASK_DEBUG=1 python run.py    auto-reload while editing (PowerShell: $env:FLASK_DEBUG = "1")
"""
import os

from app import create_app
from app.db import init_db

app = create_app()

if __name__ == "__main__":
    # Make sure the tables exist (safe to repeat) so a forgotten `init-db` cannot break the demo.
    with app.app_context():
        init_db()

    # 127.0.0.1 = this computer only, because the RA dashboard has no login in the demo.
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
