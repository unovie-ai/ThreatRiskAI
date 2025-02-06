import os

# Base directory of the application
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Upload folder configuration
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'json'}

# Database configuration
DB_DIR = os.path.join(BASE_DIR, 'db')
DB_FILE = "threats.db"

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
