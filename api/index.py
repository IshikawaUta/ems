# api/index.py

import sys
import os

# Tambahkan direktori root proyek ke PYTHONPATH agar Flask bisa menemukan app.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import instance Flask app Anda dari app.py
# Pastikan nama variabel Flask app di app.py adalah 'app'
from app import app as application # Ganti 'app' dengan nama variabel aplikasi Flask Anda

# Vercel secara otomatis akan mencari objek 'application' yang dapat dipanggil
# untuk menjalankan aplikasi WSGI/ASGI.
