from flask import Flask
from app.routes import main_blueprint

def create_app():
    app = Flask(__name__, static_folder='static', template_folder='templates')
    app.register_blueprint(main_blueprint)
    return app