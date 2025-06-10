# api/index.py

import sys
import os

# Tambahkan direktori root proyek ke PYTHONPATH agar Flask bisa menemukan app.py
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import instance Flask app Anda dari app.py
# Vercel mencari variabel bernama 'app' atau 'handler'.
# Pastikan nama variabel Flask app di app.py adalah 'app' (seperti yang sudah kita gunakan)
from app import app # Import langsung sebagai 'app'

# Vercel secara otomatis akan mencari objek 'app' atau 'handler' yang dapat dipanggil
# untuk menjalankan aplikasi WSGI/ASGI.
