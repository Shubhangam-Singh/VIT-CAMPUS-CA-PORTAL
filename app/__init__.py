"""VIT Campus CA Portal - Flask application factory.

create_app() builds the Flask object, loads the settings, connects the database helpers
and registers the pages. Later phases register their pages (admin, signing, ...) here too.
"""
from flask import Flask, render_template


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

    # Friendly error pages instead of the bare server ones.
    errors = {404: ("Page not found", "There is nothing at this address. Check the link or the tracking ID."),
              413: ("File too large", "Uploads are limited to 20 MB."),
              500: ("Something went wrong", "The server hit an unexpected error. The terminal running the portal "
                                            "shows the details.")}

    def error_page(err):
        code = getattr(err, "code", 500) or 500
        title, message = errors.get(code, errors[500])
        return render_template("error.html", code=code, title=title, message=message), code

    for code in errors:
        app.register_error_handler(code, error_page)

    return app
