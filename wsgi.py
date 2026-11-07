"""
WSGI Entry Point for Production Deployment (Gunicorn / uWSGI / Render / Railway)
"""

from app import app

if __name__ == "__main__":
    app.run()
