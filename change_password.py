#!/usr/bin/env python3
import sqlite3
import hashlib
import secrets
import sys
from pathlib import Path

def hash_password(password, salt=None):
    """Hashear contraseña"""
    if salt is None:
        salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt.encode('utf-8'), 
        100000
    )
    return salt, password_hash.hex()

def change_password(username, new_password):
    """Cambiar contraseña de usuario"""
    db_path = Path(__file__).parent / "data" / "users.db"
    
    if not db_path.exists():
        print("❌ Base de datos de usuarios no encontrada")
        return False
    
    salt, password_hash = hash_password(new_password)
    
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            'UPDATE users SET password_hash = ?, salt = ?, login_attempts = 0, locked_until = NULL WHERE username = ?',
            (password_hash, salt, username)
        )
        conn.commit()
        print(f"✅ Contraseña cambiada exitosamente para usuario: {username}")
        return True
    except Exception as e:
        print(f"❌ Error cambiando contraseña: {e}")
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python change_password.py <usuario> <nueva_contraseña>")
        sys.exit(1)
    
    username = sys.argv[1]
    new_password = sys.argv[2]
    
    change_password(username, new_password)