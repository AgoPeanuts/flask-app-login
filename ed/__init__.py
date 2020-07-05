#import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt


# Globall valiables
db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()

def create_app(test_config=None):
    """Construct the core app object."""
    app = Flask(__name__, instance_relative_config=True)

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_pyfile(test_config, silent=True)

    # Initialize objects of globall valiables
    db.init_app(app)
    login_manager.init_app(app)
    # set route for login_view
    login_manager.login_view = 'auth.login'
    bcrypt.init_app(app)

    with app.app_context():
        from .models import User
        db.create_all()

    # register blueprints
    from eb.mod_auth.views import auth
    app.register_blueprint(auth)
    from eb.mod_main.views import main
    app.register_blueprint(main)

    return app
