#!/usr/bin/env python3
import asyncio
import logging
import signal
import sys
import threading
import time
import os
import socket
import json
from pathlib import Path
from waitress import serve
from flask import Flask, jsonify, send_file

# =========================
# Configuración de LOGGING
# =========================
LOG_PATH = os.path.join(os.getcwd(), "data", "logs", "proxy.log")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# =========================
# Cargar configuración DIRECTAMENTE
# =========================
def load_config():
    """Cargar configuración directamente sin dependencias"""
    BASE_DIR = Path(__file__).parent
    
    # OBTENER PUERTO DE RENDER - CLAVE PARA FUNCIONAR
    RENDER_PORT = os.environ.get('PORT', '10000')
    
    DEFAULT_CONFIG = {
        "proxy_host": "0.0.0.0",
        "proxy_port": 8080,  # Proxy en puerto interno
        "web_host": "0.0.0.0",
        "web_port": int(RENDER_PORT),  # Dashboard usa puerto de Render
        "dashboard_domain": "familiasaldarreaga.dzknight.com",
        "dashboard_title": "Proxy Familiar - Familia Saldarreaga",
        "security": {
            "require_auth": True,
            "session_timeout": 3600,
            "max_login_attempts": 3,
            "lockout_time": 900
        },
        "database_url": f"sqlite:///{BASE_DIR}/data/proxy.db",
        "cache_enabled": True,
        "cache_size": 1000,
        "cache_ttl": 3600,
        "blocking_enabled": True,
        "youtube_blocking": True,
        "aggressive_filtering": True,
        "block_trackers": True,
        "log_level": "INFO",
        "cert_dir": str(BASE_DIR / "config" / "certs"),
        "block_lists": {
            "easylist": "https://easylist.to/easylist/easylist.txt",
            "easyprivacy": "https://easylist.to/easylist/easyprivacy.txt",
            "adguard_base": "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/base.txt",
            "adguard_annoyances": "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/sections/annoyances.txt",
            "adguard_tracking": "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt",
            "youtube_ads": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/youtube.txt",
            "malware_hosts": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
        },
        "whitelist": [
            "update.microsoft.com",
            "windowsupdate.microsoft.com",
            "microsoft.com",
            "youtube.com",
            "www.youtube.com",
            "googlevideo.com",
            "ytimg.com",
            "ggpht.com",
            "gvt1.com",
            "google.com"
        ],
        "blacklist": [
            "googleads.g.doubleclick.net",
            "connect.facebook.net",
            "ads.tiktok.com",
            "googlesyndication.com",
            "doubleclick.net",
            "googleadservices.com"
        ],
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        ]
    }
    
    config_path = BASE_DIR / "config" / "config.json"
    
    # Crear carpetas necesarias primero
    (BASE_DIR / "config").mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "data").mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "data" / "logs").mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "data" / "block_lists").mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "data" / "cache").mkdir(parents=True, exist_ok=True)

    try:
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
            
            # Combinar configuraciones
            config = DEFAULT_CONFIG.copy()
            
            # Merge profundo para diccionarios anidados
            def deep_update(default, user):
                for key, value in user.items():
                    if isinstance(value, dict) and key in default and isinstance(default[key], dict):
                        deep_update(default[key], value)
                    else:
                        default[key] = value
            
            deep_update(config, user_config)
            
            # FORZAR puerto de Render para el dashboard
            if os.environ.get('PORT'):
                config['web_port'] = int(os.environ.get('PORT'))
            
        else:
            config = DEFAULT_CONFIG.copy()
            # Guardar configuración por defecto
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            logger.info(f"Configuración por defecto creada en {config_path}")

    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Error al cargar configuración: {e}. Usando valores por defecto.")
        config = DEFAULT_CONFIG.copy()

    # Asegurar que el directorio de certificados existe
    cert_dir = config.get('cert_dir', '')
    if cert_dir:
        Path(cert_dir).mkdir(parents=True, exist_ok=True)

    return config

# =========================
# Importar otros módulos DESPUÉS de definir load_config
# =========================
try:
    from core.proxy_server import AdvancedProxyServer
    from web.app import create_web_app
    from data.database import init_database
    logger.info("✅ Módulos importados correctamente")
except ImportError as e:
    logger.error(f"Error importando módulos: {e}")
    logger.error("Asegúrate de que todos los archivos existan:")
    logger.error("- core/proxy_server.py")
    logger.error("- web/app.py") 
    logger.error("- data/database.py")
    sys.exit(1)

# =========================
# Clase principal del proxy
# =========================
class DomesticProxy:
    def __init__(self):
        self.config = load_config()
        self.proxy_server = None
        self.web_app = None
        
        # Log de configuración de puertos
        logger.info(f"🔧 Configuración de puertos - Proxy: {self.config['proxy_port']}, Web: {self.config['web_port']}")

    async def start_proxy_server(self):
        """Iniciar solo el servidor proxy"""
        try:
            logger.info("🔄 Iniciando base de datos...")
            await init_database()
            
            logger.info("🔄 Iniciando servidor proxy...")
            self.proxy_server = AdvancedProxyServer(self.config)
            await self.proxy_server.start()
            
            logger.info("✅ Servidor proxy iniciado correctamente")
        except Exception as e:
            logger.error(f"❌ Error iniciando proxy: {e}")
            raise

    def create_web_app(self):
        """Crear la aplicación web Flask"""
        try:
            logger.info("🔄 Creando aplicación web...")
            web_app = create_web_app(self.proxy_server, self.config)
            if web_app is None:
                raise ValueError("create_web_app retornó None")
            return web_app
        except Exception as e:
            logger.error(f"❌ Error creando aplicación web: {e}")
            raise

    def start_web_dashboard(self):
        """Iniciar el dashboard web"""
        try:
            # Crear la app web
            self.web_app = self.create_web_app()
            
            if self.web_app is None:
                raise ValueError("La aplicación web es None")
            
            # Iniciar servidor web con waitress
            host = self.config['web_host']
            port = self.config['web_port']
            
            logger.info(f"🌐 Iniciando dashboard web en {host}:{port}...")
            serve(self.web_app, host=host, port=port)
            
        except Exception as e:
            logger.error(f"❌ Error iniciando dashboard web: {e}")
            # Intentar crear una app de emergencia
            emergency_app = Flask(__name__)
            
            @emergency_app.route('/')
            def emergency():
                return f"""
                <html>
                <body>
                    <h1>⚠️ Proxy Familiar - Dashboard No Disponible</h1>
                    <p>Error: {str(e)}</p>
                    <p>El proxy está ejecutándose en puerto interno.</p>
                </body>
                </html>
                """
            
            logger.info("🆕 Iniciando aplicación de emergencia...")
            serve(emergency_app, host='0.0.0.0', port=self.config['web_port'])

    async def stop(self):
        """Detener todos los servicios"""
        if self.proxy_server:
            await self.proxy_server.stop()
        logger.info("🛑 Proxy detenido correctamente")

def run_proxy_server(proxy_instance):
    """Ejecutar el servidor proxy en un loop asyncio separado"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(proxy_instance.start_proxy_server())
        # Mantener el loop corriendo
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info("🛑 Recibida señal de interrupción")
    except Exception as e:
        logger.error(f"❌ Error en servidor proxy: {e}")
    finally:
        loop.close()

# =========================
# Lanzamiento principal - CORREGIDO PARA RENDER
# =========================
if __name__ == "__main__":
    # Detectar si estamos en Render
    IS_RENDER = os.environ.get('RENDER', False) or os.environ.get('PORT') is not None
    
    if IS_RENDER:
        logger.info("🚀 INICIANDO EN MODO RENDER CON PROXY...")
        logger.info(f"📍 Puerto asignado por Render: {os.environ.get('PORT')}")
        
        proxy = DomesticProxy()
        
        # EN RENDER: Ejecutar AMBOS servicios
        logger.info("🚀 Iniciando ambos servicios en Render...")
        
        # Iniciar proxy server en un hilo separado
        logger.info("🔄 Iniciando servidor proxy en hilo separado...")
        proxy_thread = threading.Thread(target=run_proxy_server, args=(proxy,), daemon=True)
        proxy_thread.start()
        
        # Esperar un poco a que el proxy se inicialice
        logger.info("⏳ Esperando inicialización del proxy...")
        time.sleep(5)
        
        # Verificar si el proxy está funcionando
        try:
            # Intentar conectar al puerto del proxy localmente
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', proxy.config['proxy_port']))
            sock.close()
            
            if result == 0:
                logger.info("✅ Proxy server funcionando correctamente")
            else:
                logger.warning("⚠️  Proxy server no responde, pero continuando...")
        except:
            logger.warning("⚠️  No se pudo verificar el proxy, continuando...")
        
        # Iniciar dashboard web en el hilo principal
        logger.info("🌐 Iniciando dashboard web...")
        proxy.start_web_dashboard()
        
    else:
        # Desarrollo local: Ambos servicios
        logger.info("🚀 INICIANDO EN MODO DESARROLLO LOCAL...")
        
        proxy = DomesticProxy()
        
        # Iniciar proxy server en un hilo separado
        logger.info("🚀 Iniciando servidor proxy en hilo separado...")
        proxy_thread = threading.Thread(target=run_proxy_server, args=(proxy,), daemon=True)
        proxy_thread.start()
        
        # Esperar un poco a que el proxy se inicialice
        time.sleep(3)
        
        # Iniciar dashboard web en el hilo principal
        logger.info("🌐 Iniciando dashboard web...")
        proxy.start_web_dashboard()
