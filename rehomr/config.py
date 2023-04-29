import os

class Config:
    ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
    #UPLOAD_FOLDER = '/home/user/projects/Stray-rehomer/rehomr/static/uploads'
    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'uploads') # GPT3
    SECRET_KEY='catdev'
    #DATABASE='/home/user/projects/Stray-rehomer/instance/rehomer.db'
    DATABASE = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)), 'instance', 'rehomer.db') # GPT3