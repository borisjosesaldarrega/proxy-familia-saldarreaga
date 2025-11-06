import aiosqlite
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ProxyDatabase:
    """Clase para gestionar la base de datos del proxy"""
    
    def __init__(self, db_path: str = "data/proxy.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
    
    async def __aenter__(self):
        self.conn = await aiosqlite.connect(self.db_path)
        # Habilitar foreign keys
        await self.conn.execute("PRAGMA foreign_keys = ON")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.conn.close()
    
    async def init_database(self):
        """Inicializar base de datos SQLite con mejoras"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Configurar pragmas para mejor rendimiento
                await db.execute("PRAGMA journal_mode = WAL")
                await db.execute("PRAGMA synchronous = NORMAL")
                await db.execute("PRAGMA cache_size = -64000")  # 64MB cache
                
                # Tabla de requests con índices
                await db.execute('''
                    CREATE TABLE IF NOT EXISTS requests (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL,
                        url TEXT NOT NULL,
                        status TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        response_time REAL,
                        user_agent TEXT,
                        client_ip TEXT
                    )
                ''')
                
                # Tabla de estadísticas
                await db.execute('''
                    CREATE TABLE IF NOT EXISTS statistics (
                        domain TEXT PRIMARY KEY,
                        total_requests INTEGER DEFAULT 0,
                        blocked_requests INTEGER DEFAULT 0,
                        allowed_requests INTEGER DEFAULT 0,
                        last_visited DATETIME,
                        avg_response_time REAL DEFAULT 0
                    )
                ''')
                
                # Tabla de configuración
                await db.execute('''
                    CREATE TABLE IF NOT EXISTS config (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        description TEXT,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Tabla de dominios bloqueados/permisos
                await db.execute('''
                    CREATE TABLE IF NOT EXISTS domain_rules (
                        domain TEXT PRIMARY KEY,
                        is_blocked BOOLEAN DEFAULT FALSE,
                        rate_limit INTEGER DEFAULT 0,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Crear índices para mejor rendimiento
                await db.execute('CREATE INDEX IF NOT EXISTS idx_requests_domain ON requests(domain)')
                await db.execute('CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp)')
                await db.execute('CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status)')
                await db.execute('CREATE INDEX IF NOT EXISTS idx_domain_rules_blocked ON domain_rules(is_blocked)')
                
                # Insertar configuración por defecto
                default_config = [
                    ('max_requests_per_minute', '100', 'Límite máximo de peticiones por minuto'),
                    ('blocked_domains', '', 'Dominios bloqueados separados por coma'),
                    ('log_level', 'INFO', 'Nivel de logging'),
                    ('retention_days', '30', 'Días de retención de logs')
                ]
                
                await db.executemany('''
                    INSERT OR IGNORE INTO config (key, value, description)
                    VALUES (?, ?, ?)
                ''', default_config)
                
                await db.commit()
                logger.info("Base de datos inicializada correctamente")
                
        except Exception as e:
            logger.error(f"Error inicializando base de datos: {e}")
            raise
    
    async def log_request(self, domain: str, url: str, status: str, 
                         response_time: Optional[float] = None,
                         user_agent: Optional[str] = None,
                         client_ip: Optional[str] = None):
        """Registrar petición en la base de datos con más información"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    '''INSERT INTO requests 
                    (domain, url, status, response_time, user_agent, client_ip) 
                    VALUES (?, ?, ?, ?, ?, ?)''',
                    (domain, url, status, response_time, user_agent, client_ip)
                )
                await db.commit()
                
                # Actualizar estadísticas de forma asíncrona
                asyncio.create_task(self._update_statistics(domain, status, response_time))
                
        except Exception as e:
            logger.error(f"Error registrando petición: {e}")
    
    async def _update_statistics(self, domain: str, status: str, response_time: Optional[float] = None):
        """Actualizar estadísticas del dominio de forma optimizada"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                is_blocked = status.upper() in ['BLOCKED', 'DENIED', 'REJECTED']
                is_allowed = status.upper() in ['ALLOWED', 'PERMITTED', 'SUCCESS']
                
                # Calcular nuevo promedio de tiempo de respuesta
                new_avg_response_time = response_time or 0
                if response_time:
                    # Obtener promedio actual para calcular nuevo promedio
                    cursor = await db.execute(
                        'SELECT avg_response_time FROM statistics WHERE domain = ?',
                        (domain,)
                    )
                    result = await cursor.fetchone()
                    if result and result[0]:
                        current_avg = result[0]
                        # Promedio móvil simple
                        new_avg_response_time = (current_avg + response_time) / 2
                
                await db.execute('''
                    INSERT INTO statistics 
                    (domain, total_requests, blocked_requests, allowed_requests, last_visited, avg_response_time)
                    VALUES (?, 1, ?, ?, ?, ?)
                    ON CONFLICT(domain) DO UPDATE SET
                        total_requests = total_requests + 1,
                        blocked_requests = blocked_requests + ?,
                        allowed_requests = allowed_requests + ?,
                        last_visited = ?,
                        avg_response_time = ?
                ''', (
                    domain, 
                    1 if is_blocked else 0,
                    1 if is_allowed else 0,
                    datetime.now(),
                    new_avg_response_time,
                    1 if is_blocked else 0,
                    1 if is_allowed else 0,
                    datetime.now(),
                    new_avg_response_time
                ))
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error actualizando estadísticas: {e}")
    
    async def get_domain_stats(self, domain: str) -> Optional[Dict[str, Any]]:
        """Obtener estadísticas de un dominio específico"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    'SELECT * FROM statistics WHERE domain = ?',
                    (domain,)
                )
                row = await cursor.fetchone()
                if row:
                    columns = [description[0] for description in cursor.description]
                    return dict(zip(columns, row))
                return None
        except Exception as e:
            logger.error(f"Error obteniendo estadísticas: {e}")
            return None
    
    async def get_top_domains(self, limit: int = 10) -> list:
        """Obtener los dominios más visitados"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute('''
                    SELECT domain, total_requests, blocked_requests, 
                           (blocked_requests * 100.0 / total_requests) as block_rate
                    FROM statistics 
                    ORDER BY total_requests DESC 
                    LIMIT ?
                ''', (limit,))
                return await cursor.fetchall()
        except Exception as e:
            logger.error(f"Error obteniendo top dominios: {e}")
            return []
    
    async def cleanup_old_records(self, retention_days: int = 30):
        """Limpiar registros antiguos"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cutoff_date = datetime.now().timestamp() - (retention_days * 24 * 60 * 60)
                await db.execute(
                    'DELETE FROM requests WHERE timestamp < datetime(?, "unixepoch")',
                    (cutoff_date,)
                )
                await db.commit()
                logger.info(f"Registros antiguos eliminados (retención: {retention_days} días)")
        except Exception as e:
            logger.error(f"Error limpiando registros: {e}")
    
    async def get_config_value(self, key: str, default: str = "") -> str:
        """Obtener valor de configuración"""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    'SELECT value FROM config WHERE key = ?',
                    (key,)
                )
                result = await cursor.fetchone()
                return result[0] if result else default
        except Exception as e:
            logger.error(f"Error obteniendo configuración: {e}")
            return default

# Funciones de conveniencia para compatibilidad con código existente
async def init_database():
    """Función de inicialización compatible con la versión anterior"""
    db = ProxyDatabase()
    await db.init_database()

async def log_request(domain: str, url: str, status: str, **kwargs):
    """Función de log compatible con la versión anterior"""
    db = ProxyDatabase()
    await db.log_request(domain, url, status, **kwargs)

async def update_statistics(domain: str, blocked: bool = False):
    """Función de estadísticas compatible con la versión anterior"""
    status = "BLOCKED" if blocked else "ALLOWED"
    db = ProxyDatabase()
    await db._update_statistics(domain, status)
