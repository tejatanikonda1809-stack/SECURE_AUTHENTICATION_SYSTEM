import os

from secureauth import create_app
from secureauth.db import init_db

app = create_app()

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "").lower() == "true",
    )
