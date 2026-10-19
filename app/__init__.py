"""VIT Campus CA Portal - Flask application factory.

create_app() builds the Flask object, loads the settings, connects the database helpers
and registers the pages. Later phases register their pages (admin, signing, ...) here too.
"""
from flask import Flask


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object("app.config.Config")
    if test_config:                       # tests pass their own settings (e.g. a temporary database)
        app.config.update(test_config)

    from . import db
    db.init_app(app)

    from . import routes_admin, routes_user
    app.register_blueprint(routes_user.bp)
    app.register_blueprint(routes_admin.bp)

    return app
