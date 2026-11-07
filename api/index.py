import os
import sys

# Ensure parent directory is in sys.path for Vercel Serverless environment
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from app import app

# Vercel looks for 'app' in api/index.py
if __name__ == "__main__":
    app.run()
