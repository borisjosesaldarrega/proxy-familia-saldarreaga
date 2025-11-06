import sqlite3
import aiosqlite
from datetime import datetime
from pathlib import Path

async def init_database():
    """Inicializar base de datos SQLite"""
    db_path = Path("data/proxy.db")
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    async with aiosqlite.connect(db_path) as db:
        await db.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                url TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        await db.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                domain TEXT PRIMARY KEY,
                total_requests INTEGER DEFAULT 0,
                blocked_requests INTEGER DEFAULT 0,
                last_visited DATETIME
            )
        ''')
        
        await db.execute('''
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        
        await db.commit()

async def log_request(domain: str, url: str, status: str):
    """Registrar petición en la base de datos"""
    async with aiosqlite.connect('data/proxy.db') as db:
        await db.execute(
            'INSERT INTO requests (domain, url, status) VALUES (?, ?, ?)',
            (domain, url, status)
        )
        await db.commit()

async def update_statistics(domain: str, blocked: bool = False):
    """Actualizar estadísticas del dominio"""
    async with aiosqlite.connect('data/proxy.db') as db:
        # Insertar o actualizar estadísticas
        await db.execute('''
            INSERT INTO statistics (domain, total_requests, blocked_requests, last_visited)
            VALUES (?, 1, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                total_requests = total_requests + 1,
                blocked_requests = blocked_requests + ?,
                last_visited = ?
        ''', (domain, 1 if blocked else 0, datetime.now(), 1 if blocked else 0, datetime.now()))
        
        await db.commit()