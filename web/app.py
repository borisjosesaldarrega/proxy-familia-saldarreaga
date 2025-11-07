# web/app.py
from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
import logging
import os
import secrets
import sys
import json
import hashlib
import hmac
import time
from functools import wraps
import html

# Añadir el directorio raíz al path de Python
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Configurar logger local
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

DB_PATH = PROJECT_ROOT / "data" / "proxy.db"

# Configuración de seguridad
SECURITY_CONFIG = {
    'admin_username': 'admin',
    'session_timeout': 3600,  # 1 hora
    'max_login_attempts': 3,
    'lockout_time': 900,  # 15 minutos
    'csrf_token_expiry': 1800,  # 30 minutos
}

# Funciones de seguridad
def generate_csrf_token():
    """Generar token CSRF seguro"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
        session['csrf_token_expiry'] = time.time() + SECURITY_CONFIG['csrf_token_expiry']
    return session['csrf_token']

def validate_csrf_token(token):
    """Validar token CSRF"""
    if 'csrf_token' not in session or 'csrf_token_expiry' not in session:
        return False
    
    if time.time() > session['csrf_token_expiry']:
        session.pop('csrf_token', None)
        session.pop('csrf_token_expiry', None)
        return False
    
    return hmac.compare_digest(session['csrf_token'], token)

def hash_password(password, salt=None):
    """Hashear contraseña con salt"""
    if salt is None:
        salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        salt.encode('utf-8'), 
        100000  # 100,000 iteraciones
    )
    return salt, password_hash.hex()

def verify_password(password, salt, stored_hash):
    """Verificar contraseña"""
    _, new_hash = hash_password(password, salt)
    return hmac.compare_digest(new_hash, stored_hash)

def login_required(f):
    """Decorator para requerir autenticación"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            logger.warning(f"Acceso no autorizado a {request.endpoint}. Redirigiendo a login.")
            return redirect(url_for('login'))
        
        # Verificar timeout de sesión
        login_time = session.get('login_time', 0)
        if time.time() - login_time > SECURITY_CONFIG['session_timeout']:
            logger.info(f"Sesión expirada para usuario: {session.get('username')}")
            session.clear()
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator para requerir rol admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return jsonify({'error': 'No autenticado'}), 401
        if session.get('role') != 'admin':
            return jsonify({'error': 'Acceso no autorizado'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Funciones de configuración como fallback
def load_config_fallback():
    """Cargar configuración como fallback"""
    config_path = PROJECT_ROOT / "config" / "config.json"
    default_config = {
        "proxy_host": "0.0.0.0",
        "proxy_port": 8080,
        "web_host": "0.0.0.0", 
        "web_port": 10000,  # Cambiado para Render
        "blocking_enabled": True,
        "whitelist": [],
        "blacklist": [],
        "dashboard_domain": "familiasaldarreaga.dzknight.com",
        "dashboard_title": "Proxy Familiar - Familia Saldarreaga",
        "security": {
            "require_auth": True,
            "session_timeout": 3600
        }
    }
    
    try:
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
            # Combinar configuraciones
            config = default_config.copy()
            config.update(user_config)
            
            # Asegurar puerto correcto para Render
            if os.environ.get('PORT'):
                config['web_port'] = 10000  # Dashboard en puerto diferente al proxy
                
            return config
    except Exception as e:
        logger.warning(f"Error cargando configuración: {e}")
    
    return default_config

def add_to_blacklist_fallback(domain):
    """Añadir a blacklist como fallback"""
    config = load_config_fallback()
    if domain not in config.get('blacklist', []):
        config['blacklist'] = config.get('blacklist', []) + [domain]
        try:
            config_path = PROJECT_ROOT / "config" / "config.json"
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            logger.info(f"Dominio añadido a blacklist: {domain}")
        except Exception as e:
            logger.error(f"Error guardando blacklist: {e}")

def add_to_whitelist_fallback(domain):
    """Añadir a whitelist como fallback"""
    config = load_config_fallback()
    if domain not in config.get('whitelist', []):
        config['whitelist'] = config.get('whitelist', []) + [domain]
        try:
            config_path = PROJECT_ROOT / "config" / "config.json"
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            logger.info(f"Dominio añadido a whitelist: {domain}")
        except Exception as e:
            logger.error(f"Error guardando whitelist: {e}")

# Intentar importar las funciones reales
try:
    from setting import add_to_blacklist, add_to_whitelist, load_config
    logger.info("✅ Módulo setting cargado correctamente")
except ImportError as e:
    logger.warning(f"❌ No se pudo cargar setting.py: {e}, usando funciones fallback")
    # Usar funciones fallback
    add_to_blacklist = add_to_blacklist_fallback
    add_to_whitelist = add_to_whitelist_fallback
    load_config = load_config_fallback

def _open_db():
    """Abrir conexión a la base de datos con manejo de errores"""
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH), detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
        conn.row_factory = sqlite3.Row  # Para acceso por nombre de columna
        return conn
    except Exception as e:
        logger.error(f"Error abriendo base de datos: {e}")
        raise

def create_web_app(proxy_server: Optional[Any] = None, config: Optional[Dict[str, Any]] = None) -> Flask:
    """Crear aplicación Flask optimizada para Render"""
    try:
        app = Flask(__name__, 
                    template_folder=str(PROJECT_ROOT / "web" / "templates"),
                    static_folder=str(PROJECT_ROOT / "web" / "static"))
        
        # CONFIGURACIÓN CRÍTICA CORREGIDA - SESSIONES
        app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
        
        # Configuración de cookies y sesiones CORREGIDA
        app.config.update(
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SECURE=False,  # IMPORTANTE: False para desarrollo y Render sin HTTPS personalizado
            SESSION_COOKIE_SAMESITE='Lax',
            PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
            SESSION_REFRESH_EACH_REQUEST=True,
            # Configuraciones adicionales para estabilidad
            USE_X_SENDFILE=False,
            MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB max upload
        )

        # Si no se pasa config, cargarla
        if config is None:
            config = load_config()

        # Asegurar directorios necesarios
        required_dirs = [
            PROJECT_ROOT / "data",
            PROJECT_ROOT / "data" / "logs", 
            PROJECT_ROOT / "config",
            PROJECT_ROOT / "web" / "templates",
            PROJECT_ROOT / "web" / "static"
        ]
        
        for dir_path in required_dirs:
            dir_path.mkdir(parents=True, exist_ok=True)

        # Inicializar base de datos de usuarios
        def init_user_db():
            """Inicializar base de datos de usuarios"""
            try:
                user_db_path = PROJECT_ROOT / "data" / "users.db"
                conn = sqlite3.connect(str(user_db_path))
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        role TEXT DEFAULT 'user',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        login_attempts INTEGER DEFAULT 0,
                        locked_until TIMESTAMP
                    )
                ''')

                # Crear usuario admin por defecto si no existe
                cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', (SECURITY_CONFIG['admin_username'],))
                if cursor.fetchone()[0] == 0:
                    salt, password_hash = hash_password('admin123')  # Contraseña por defecto
                    cursor.execute(
                        'INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)',
                        (SECURITY_CONFIG['admin_username'], password_hash, salt, 'admin')
                    )
                    logger.info("✅ Usuario admin creado con contraseña por defecto: admin123")
                
                conn.commit()
                conn.close()
                logger.info("✅ Base de datos de usuarios inicializada")
            except Exception as e:
                logger.error(f"❌ Error inicializando base de datos de usuarios: {e}")
        
        init_user_db()

        @app.before_request
        def before_request():
            """Ejecutar antes de cada request - CORREGIDO"""
            # Solo verificar timeout para rutas que requieren autenticación
            if session.get('authenticated'):
                login_time = session.get('login_time', 0)
                current_time = time.time()
                
                # Verificar timeout de sesión
                if current_time - login_time > SECURITY_CONFIG['session_timeout']:
                    username = session.get('username', 'Unknown')
                    logger.info(f"Sesión expirada para {username}. Limpiando sesión.")
                    session.clear()
                    if request.endpoint and not request.endpoint.startswith(('login', 'static', 'health')):
                        return redirect(url_for('login'))
                else:
                    # Refresh session para mantenerla activa
                    session.modified = True
            
            # Generar CSRF token para forms (excepto para archivos estáticos)
            if request.endpoint and request.endpoint != 'static':
                generate_csrf_token()

        @app.route('/login', methods=['GET', 'POST'])
        def login():
            """Página de login - MEJORADO"""
            # Si ya está autenticado y la sesión es válida, redirigir al dashboard
            if session.get('authenticated'):
                login_time = session.get('login_time', 0)
                if time.time() - login_time <= SECURITY_CONFIG['session_timeout']:
                    logger.info(f"Usuario {session.get('username')} ya autenticado, redirigiendo a dashboard")
                    return redirect(url_for('dashboard'))
                else:
                    # Sesión expirada, limpiar
                    session.clear()
            
            if request.method == 'POST':
                username = request.form.get('username', '').strip()
                password = request.form.get('password', '')
                csrf_token = request.form.get('csrf_token', '')
                
                logger.info(f"Intento de login para usuario: {username}")
                
                # Validar CSRF token
                if not validate_csrf_token(csrf_token):
                    logger.warning(f"Token CSRF inválido para usuario: {username}")
                    return render_template('login.html', 
                                        error="Token de seguridad inválido. Recarga la página.",
                                        csrf_token=generate_csrf_token())
                
                # Verificar credenciales
                user_db_path = PROJECT_ROOT / "data" / "users.db"
                conn = sqlite3.connect(str(user_db_path))
                cursor = conn.cursor()
                
                try:
                    cursor.execute(
                        'SELECT username, password_hash, salt, role, login_attempts, locked_until FROM users WHERE username = ?',
                        (username,)
                    )
                    user = cursor.fetchone()
                    
                    if user:
                        username_db, password_hash, salt, role, login_attempts, locked_until = user
                        
                        # Verificar si la cuenta está bloqueada
                        if locked_until and datetime.fromisoformat(locked_until) > datetime.now():
                            remaining_time = (datetime.fromisoformat(locked_until) - datetime.now()).seconds // 60
                            logger.warning(f"Cuenta bloqueada para usuario: {username}")
                            return render_template('login.html',
                                                error=f"Cuenta bloqueada. Intente nuevamente en {remaining_time} minutos",
                                                csrf_token=generate_csrf_token())
                        
                        # Verificar contraseña
                        if verify_password(password, salt, password_hash):
                            # LOGIN EXITOSO - Configurar sesión correctamente
                            session.clear()  # Limpiar sesión anterior
                            session['authenticated'] = True
                            session['username'] = username
                            session['role'] = role
                            session['login_time'] = time.time()
                            session['session_id'] = secrets.token_urlsafe(32)
                            
                            # Forzar escritura de la sesión
                            session.modified = True
                            
                            # Resetear intentos fallidos
                            cursor.execute(
                                'UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE username = ?',
                                (username,)
                            )
                            conn.commit()
                            conn.close()
                            
                            logger.info(f"✅ Login exitoso para usuario: {username}")
                            return redirect(url_for('dashboard'))
                        else:
                            # Login fallido
                            login_attempts += 1
                            if login_attempts >= SECURITY_CONFIG['max_login_attempts']:
                                locked_until = (datetime.now() + timedelta(seconds=SECURITY_CONFIG['lockout_time'])).isoformat()
                                cursor.execute(
                                    'UPDATE users SET login_attempts = ?, locked_until = ? WHERE username = ?',
                                    (login_attempts, locked_until, username)
                                )
                                error_msg = "Demasiados intentos fallidos. Cuenta bloqueada por 15 minutos."
                                logger.warning(f"Cuenta bloqueada por intentos fallidos: {username}")
                            else:
                                cursor.execute(
                                    'UPDATE users SET login_attempts = ? WHERE username = ?',
                                    (login_attempts, username)
                                )
                                error_msg = f"Credenciales inválidas. Intentos restantes: {SECURITY_CONFIG['max_login_attempts'] - login_attempts}"
                                logger.warning(f"Intento fallido {login_attempts} para usuario: {username}")
                            
                            conn.commit()
                            conn.close()
                            return render_template('login.html', error=error_msg, csrf_token=generate_csrf_token())
                    else:
                        conn.close()
                        logger.warning(f"Usuario no encontrado: {username}")
                        return render_template('login.html', error="Credenciales inválidas", csrf_token=generate_csrf_token())
                        
                except Exception as e:
                    logger.error(f"Error en login para {username}: {e}")
                    conn.close()
                    return render_template('login.html', error="Error interno del servidor", csrf_token=generate_csrf_token())
            
            # GET request - mostrar formulario de login
            csrf_token = generate_csrf_token()
            return render_template('login.html', csrf_token=csrf_token)

        @app.route('/logout')
        def logout():
            """Cerrar sesión - MEJORADO"""
            username = session.get('username', 'Unknown')
            session.clear()
            logger.info(f"Logout exitoso para usuario: {username}")
            return redirect(url_for('login'))

        @app.route('/')
        @login_required
        def dashboard():
            """Panel principal"""
            # Verificación adicional de autenticación
            if not session.get('authenticated'):
                return redirect(url_for('login'))
                
            stats = {}
            try:
                if proxy_server and hasattr(proxy_server, "get_stats"):
                    stats = proxy_server.get_stats()
            except Exception as e:
                logger.warning(f"No se pudieron obtener estadísticas: {e}")

            conn = _open_db()
            cursor = conn.cursor()

            try:
                # Verificar si la tabla existe y tiene datos
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='requests'")
                table_exists = cursor.fetchone()
                
                if not table_exists:
                    # Si la tabla no existe, crear datos vacíos
                    recent_logs = []
                    top_domains = []
                    domain_count = 0
                else:
                    # Logs recientes
                    cursor.execute('''
                        SELECT domain, url, status, timestamp 
                        FROM requests 
                        ORDER BY timestamp DESC 
                        LIMIT 100
                    ''')
                    recent_logs = cursor.fetchall()

                    # Top dominios
                    cursor.execute('''
                        SELECT domain, COUNT(*) as count 
                        FROM requests 
                        WHERE datetime(timestamp) > datetime('now', '-1 day')
                        GROUP BY domain 
                        ORDER BY count DESC 
                        LIMIT 20
                    ''')
                    top_domains = cursor.fetchall()

                    # Contar dominios únicos
                    cursor.execute('SELECT COUNT(DISTINCT domain) FROM requests')
                    domain_count_result = cursor.fetchone()
                    domain_count = domain_count_result[0] if domain_count_result else 0
                    
            except Exception as e:
                logger.error(f"Error en consultas de dashboard: {e}")
                recent_logs = []
                top_domains = []
                domain_count = 0
            finally:
                conn.close()

            # Asegurar que stats tenga los campos necesarios
            if not stats:
                stats = {
                    'total_requests': 0,
                    'blocked_requests': 0,
                    'cached_responses': 0,
                    'unique_domains': domain_count
                }
            else:
                # Actualizar el conteo de dominios únicos
                stats['unique_domains'] = domain_count

            return render_template(
                'dashboard.html',
                stats=stats,
                recent_logs=recent_logs,
                top_domains=top_domains,
                config=config,
                username=session.get('username'),
                role=session.get('role'),
                csrf_token=generate_csrf_token()
            )

        @app.route('/api/clear_cache', methods=['POST'])
        @login_required
        def clear_cache():
            """Limpia la caché del proxy - requiere autenticación"""
            try:
                cache_dir = PROJECT_ROOT / "data" / "cache"
                cache_dir.mkdir(parents=True, exist_ok=True)

                removed = 0
                for file in cache_dir.glob("*"):
                    try:
                        if file.is_file():
                            file.unlink()
                            removed += 1
                    except Exception as e:
                        logger.warning(f"No se pudo eliminar {file}: {e}")

                return jsonify({
                    "status": "success", 
                    "message": f"Caché limpiada correctamente. Archivos eliminados: {removed}"
                })
            except Exception as e:
                logger.error(f"Error al limpiar cache: {e}")
                return jsonify({"status": "error", "message": str(e)}), 500

        @app.route('/api/stats')
        @login_required
        def api_stats():
            """API para estadísticas - requiere autenticación"""
            try:
                if proxy_server and hasattr(proxy_server, "get_stats"):
                    return jsonify(proxy_server.get_stats())
            except Exception as e:
                logger.warning(f"Error al obtener estadísticas: {e}")
            return jsonify({})

        @app.route('/api/block', methods=['POST'])
        @login_required
        def api_block():
            """API para bloquear dominio - requiere autenticación"""
            data = request.get_json(silent=True) or {}
            
            # Validar CSRF token para acciones críticas
            if not validate_csrf_token(data.get('csrf_token', '')):
                return jsonify({'status': 'error', 'message': 'Token de seguridad inválido'}), 403
            
            domain = data.get('domain')
            
            if domain:
                try:
                    # Método 1: Si el proxy tiene content_filter
                    if proxy_server and hasattr(proxy_server, "content_filter"):
                        proxy_server.content_filter.add_to_blacklist(domain)
                    
                    # Método 2: Guardar en configuración
                    add_to_blacklist(domain)
                    
                    return jsonify({
                        'status': 'success', 
                        'message': f'Dominio bloqueado: {domain}'
                    })
                except Exception as e:
                    logger.error(f"Error al bloquear dominio {domain}: {e}")
                    return jsonify({'status': 'error', 'message': str(e)}), 500
            
            return jsonify({'status': 'error', 'message': 'Dominio no proporcionado'}), 400

        @app.route('/api/allow', methods=['POST'])
        @login_required
        def api_allow():
            """API para permitir dominio - requiere autenticación"""
            data = request.get_json(silent=True) or {}
            
            # Validar CSRF token para acciones críticas
            if not validate_csrf_token(data.get('csrf_token', '')):
                return jsonify({'status': 'error', 'message': 'Token de seguridad inválido'}), 403
            
            domain = data.get('domain')
            
            if domain:
                try:
                    # Método 1: Si el proxy tiene content_filter
                    if proxy_server and hasattr(proxy_server, "content_filter"):
                        proxy_server.content_filter.add_to_whitelist(domain)
                    
                    # Método 2: Guardar en configuración
                    add_to_whitelist(domain)
                    
                    return jsonify({
                        'status': 'success', 
                        'message': f'Dominio permitido: {domain}'
                    })
                except Exception as e:
                    logger.error(f"Error al permitir dominio {domain}: {e}")
                    return jsonify({'status': 'error', 'message': str(e)}), 500
            
            return jsonify({'status': 'error', 'message': 'Dominio no proporcionado'}), 400

        @app.route('/api/config', methods=['POST'])
        @login_required
        def api_config():
            """API para modificar configuración - requiere autenticación"""
            data = request.get_json(silent=True) or {}
            
            # Validar CSRF token para acciones críticas
            if not validate_csrf_token(data.get('csrf_token', '')):
                return jsonify({'status': 'error', 'message': 'Token de seguridad inválido'}), 403
            
            key = data.get('key')
            value = data.get('value')

            if isinstance(config, dict) and key in config and key not in ['proxy_host', 'proxy_port']:
                config[key] = value
                # Guardar cambios en archivo
                try:
                    from setting import save_config
                    save_config(config)
                except ImportError:
                    # Fallback: guardar manualmente
                    try:
                        config_path = PROJECT_ROOT / "config" / "config.json"
                        config_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(config_path, 'w', encoding='utf-8') as f:
                            json.dump(config, f, indent=4, ensure_ascii=False)
                    except Exception as e:
                        logger.error(f"Error guardando configuración: {e}")
                
                return jsonify({'status': 'success'})

            return jsonify({'status': 'error', 'message': 'Configuración no válida'}), 400

        @app.route('/api/export_logs')
        @login_required
        def export_logs():
            """Exportar logs en formato JSON - requiere autenticación"""
            try:
                conn = _open_db()
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT domain, url, status, timestamp 
                    FROM requests 
                    ORDER BY timestamp DESC 
                    LIMIT 1000
                ''')
                logs = cursor.fetchall()
                conn.close()
                
                # Convertir a formato JSON amigable
                log_data = []
                for log in logs:
                    log_data.append({
                        'domain': log[0],
                        'url': log[1],
                        'status': log[2],
                        'timestamp': log[3].isoformat() if isinstance(log[3], datetime) else str(log[3])
                    })
                
                return jsonify({
                    'status': 'success',
                    'logs': log_data,
                    'count': len(log_data),
                    'exported_at': datetime.now().isoformat()
                })
            except Exception as e:
                logger.error(f"Error exportando logs: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 500

        @app.route('/api/filter_lists')
        @login_required
        def get_filter_lists():
            """Obtener listas actuales de bloqueo y permitidos - requiere autenticación"""
            try:
                # Primero intentar obtener del proxy si existe
                if proxy_server and hasattr(proxy_server, "content_filter"):
                    blacklist = getattr(proxy_server.content_filter, 'blacklist', [])
                    whitelist = getattr(proxy_server.content_filter, 'whitelist', [])
                    
                    return jsonify({
                        'blacklist': list(blacklist),
                        'whitelist': list(whitelist),
                        'counts': {
                            'blacklisted': len(blacklist),
                            'whitelisted': len(whitelist)
                        }
                    })
            except Exception as e:
                logger.error(f"Error obteniendo listas del proxy: {e}")
            
            # Fallback: obtener del archivo de configuración
            try:
                current_config = load_config()
                return jsonify({
                    'blacklist': current_config.get('blacklist', []),
                    'whitelist': current_config.get('whitelist', []),
                    'counts': {
                        'blacklisted': len(current_config.get('blacklist', [])),
                        'whitelisted': len(current_config.get('whitelist', []))
                    }
                })
            except Exception as e:
                logger.error(f"Error obteniendo listas de configuración: {e}")
                return jsonify({
                    'blacklist': [], 
                    'whitelist': [], 
                    'counts': {
                        'blacklisted': 0, 
                        'whitelisted': 0
                    }
                })

        @app.route('/api/reset_stats', methods=['POST'])
        @login_required
        def reset_stats():
            """Reiniciar contadores de estadísticas - requiere autenticación"""
            data = request.get_json(silent=True) or {}
            
            # Validar CSRF token para acciones críticas
            if not validate_csrf_token(data.get('csrf_token', '')):
                return jsonify({'status': 'error', 'message': 'Token de seguridad inválido'}), 403
            
            try:
                if proxy_server and hasattr(proxy_server, "reset_stats"):
                    proxy_server.reset_stats()
                    return jsonify({
                        'status': 'success', 
                        'message': 'Estadísticas reiniciadas'
                    })
            except Exception as e:
                logger.error(f"Error reiniciando stats: {e}")
                return jsonify({'status': 'error', 'message': str(e)}), 500
            
            return jsonify({
                'status': 'error', 
                'message': 'Función no disponible'
            }), 400

        @app.route('/api/change_password', methods=['POST'])
        @login_required
        def change_password_api():
            """Cambiar contraseña del usuario actual - requiere autenticación"""
            data = request.get_json(silent=True) or {}
            
            # Validar CSRF token para acciones críticas
            if not validate_csrf_token(data.get('csrf_token', '')):
                return jsonify({'status': 'error', 'message': 'Token de seguridad inválido'}), 403
            
            current_password = data.get('current_password')
            new_password = data.get('new_password')
            confirm_password = data.get('confirm_password')
            
            if not all([current_password, new_password, confirm_password]):
                return jsonify({'status': 'error', 'message': 'Todos los campos son requeridos'}), 400
            
            if new_password != confirm_password:
                return jsonify({'status': 'error', 'message': 'Las contraseñas nuevas no coinciden'}), 400
            
            if len(new_password) < 8:
                return jsonify({'status': 'error', 'message': 'La contraseña debe tener al menos 8 caracteres'}), 400
            
            # Verificar contraseña actual y cambiar
            user_db_path = PROJECT_ROOT / "data" / "users.db"
            conn = sqlite3.connect(str(user_db_path))
            cursor = conn.cursor()
            
            try:
                cursor.execute(
                    'SELECT password_hash, salt FROM users WHERE username = ?',
                    (session.get('username'),)
                )
                user = cursor.fetchone()
                
                if user:
                    stored_hash, salt = user
                    if verify_password(current_password, salt, stored_hash):
                        # Cambiar contraseña
                        new_salt, new_hash = hash_password(new_password)
                        cursor.execute(
                            'UPDATE users SET password_hash = ?, salt = ? WHERE username = ?',
                            (new_hash, new_salt, session.get('username'))
                        )
                        conn.commit()
                        conn.close()
                        
                        logger.info(f"Contraseña cambiada para usuario: {session.get('username')}")
                        return jsonify({'status': 'success', 'message': 'Contraseña cambiada exitosamente'})
                    else:
                        conn.close()
                        return jsonify({'status': 'error', 'message': 'Contraseña actual incorrecta'}), 400
                else:
                    conn.close()
                    return jsonify({'status': 'error', 'message': 'Usuario no encontrado'}), 404
                    
            except Exception as e:
                conn.close()
                logger.error(f"Error cambiando contraseña: {e}")
                return jsonify({'status': 'error', 'message': 'Error interno del servidor'}), 500

        @app.route('/api/session_info')
        @login_required
        def session_info():
            """Obtener información de la sesión actual - requiere autenticación"""
            return jsonify({
                'username': session.get('username'),
                'role': session.get('role'),
                'login_time': session.get('login_time'),
                'session_expires': session.get('login_time', 0) + SECURITY_CONFIG['session_timeout'],
                'csrf_token': generate_csrf_token(),
                'authenticated': True
            })

        @app.route('/api/check_session')
        def check_session():
            """Verificar si hay una sesión activa - público"""
            if session.get('authenticated'):
                login_time = session.get('login_time', 0)
                if time.time() - login_time <= SECURITY_CONFIG['session_timeout']:
                    return jsonify({
                        'authenticated': True,
                        'username': session.get('username'),
                        'role': session.get('role'),
                        'login_time': session.get('login_time')
                    })
                else:
                    # Sesión expirada
                    session.clear()
                    
            return jsonify({'authenticated': False})

        @app.route('/logs')
        @login_required
        def view_logs():
            """Ver logs detallados - requiere autenticación"""
            conn = _open_db()
            cursor = conn.cursor()

            page = request.args.get('page', 1, type=int)
            limit = 100
            offset = (page - 1) * limit

            cursor.execute('''
                SELECT domain, url, status, timestamp 
                FROM requests 
                ORDER BY timestamp DESC 
                LIMIT ? OFFSET ?
            ''', (limit, offset))
            logs = cursor.fetchall()

            cursor.execute('SELECT COUNT(*) FROM requests')
            total_row = cursor.fetchone()
            total = total_row[0] if total_row else 0

            conn.close()

            return render_template('logs.html', 
                                logs=logs, 
                                page=page, 
                                total=total, 
                                limit=limit,
                                username=session.get('username'),
                                role=session.get('role'),
                                csrf_token=generate_csrf_token())

        @app.route('/health')
        def health_check():
            """Endpoint de salud para Render"""
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'environment': 'production' if os.environ.get('RENDER') else 'development',
                'service': 'proxy-dashboard'
            })

        @app.route('/test')
        def test():
            return jsonify({
                'status': 'success',
                'message': '✅ Flask está funcionando correctamente',
                'project_root': str(PROJECT_ROOT),
                'database_exists': DB_PATH.exists(),
                'render_environment': bool(os.environ.get('RENDER'))
            })
            
        logger.info("✅ Aplicación Flask creada correctamente para Render")
        return app
        
    except Exception as e:
        logger.error(f"❌ Error crítico creando aplicación Flask: {e}")
        # Crear una app mínima de emergencia
        emergency_app = Flask(__name__)
        emergency_app.secret_key = 'emergency-key'
        
        @emergency_app.route('/')
        def emergency():
            return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Modo Emergencia - Proxy Familiar</title>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 100px auto; padding: 20px; }}
                    .alert {{ background: #fff3f3; padding: 20px; border-radius: 8px; border-left: 4px solid #ff4444; }}
                    .error {{ background: #f8f9fa; padding: 15px; margin: 15px 0; font-family: monospace; }}
                </style>
            </head>
            <body>
                <div class="alert">
                    <h1>⚠️ Sistema en Mantenimiento</h1>
                    <p>Estamos experimentando problemas técnicos. Por favor, intente más tarde.</p>
                    <div class="error">Error: {html.escape(str(e))}</div>
                    <p><a href="/health">Ver estado del servicio</a></p>
                </div>
            </body>
            </html>
            """
            
        @emergency_app.route('/health')
        def emergency_health():
            return jsonify({'status': 'degraded', 'message': 'Emergency mode active'})
            
        return emergency_app
