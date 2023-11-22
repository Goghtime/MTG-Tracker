from app import app, db
from flask_migrate import Migrate

migrate = Migrate(app, db)  # Initialize Flask-Migrate

if __name__ == '__main__':
    app.debug = True  # Remove this before deploying to production
    app.run(host='0.0.0.0', port=5000)
