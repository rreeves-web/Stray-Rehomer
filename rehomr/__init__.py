import os
from flask import Flask


def create_app(test_config=None):
    # create and configure app
    app = Flask(__name__, instance_relative_config=True)
    
    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_mapping(DATABASE=os.path.join(app.instance_path, 'rehomr.db'),
        UPLOAD_FOLDER = os.path.abspath(os.path.join(app.root_path, 'static', 'uploads')),
        SECRET_KEY='catdev',
        ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
        )
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)
    
    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    from . import db
    db.init_app(app)
    from . import auth
    app.register_blueprint(auth.bp)
    from . import rehomr
    app.register_blueprint(rehomr.bp)
    app.add_url_rule('/', endpoint='index')

    return app