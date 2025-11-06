#!/usr/bin/env python3
import asyncio
import logging
import signal
import sys
import threading
import time
import os
import socket
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
# Importar setting.py PRIMERO
# =========================
try:
    from config import load_config, save_config, add_to_blacklist, add_to_whitelist
    logger.info("✅ config.py cargado correctamente")
except ImportError as e:
    logger.error(f"❌ Error importando config.py: {e}")
    sys.exit(1)

# =========================
# Importar otros módulos
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
# Servidor Flask auxiliar
# =========================
log_app = Flask(__name__)

@log_app.route("/logs")
def ver_logs():
    """Ver logs en el navegador"""
    if not os.path.exists(LOG_PATH):
        return jsonify({"error": "El archivo de logs no existe"}), 404
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        contenido = f.read()
    return f"<pre>{contenido}</pre>"

@log_app.route("/logs/download")
def descargar_logs():
    """Descargar el archivo de logs"""
    if not os.path.exists(LOG_PATH):
        return jsonify({"error": "El archivo de logs no existe"}), 404
    return send_file(LOG_PATH, as_attachment=True)

# =========================
# Clase principal del proxy
# =========================
class DomesticProxy:
    def __init__(self):
        # Cargar configuración desde setting.py
        self.config = load_config()
        
        # AJUSTAR PUERTOS PARA RENDER
        render_port = os.environ.get('PORT')
        if render_port:
            logger.info(f"🔄 Ajustando puertos para Render: {render_port}")
            self.config['proxy_port'] = int(render_port)
            self.config['web_port'] = 10000  # Puerto diferente para el dashboard
        
        self.proxy_server = None
        self.web_app = None

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
                    <h1>⚠️ Error en el Dashboard</h1>
                    <p>El dashboard principal no está disponible.</p>
                    <p>Error: {str(e)}</p>
                    <p><a href="/logs">Ver logs</a></p>
                </body>
                </html>
                """
            
            logger.info("🆕 Iniciando aplicación de emergencia...")
            serve(emergency_app, host='0.0.0.0', port=10000)

    async def stop(self):
        """Detener todos los servicios"""
        if self.proxy_server:
            await self.proxy_server.stop()
        logger.info("🛑 Proxy detenido correctamente")

    def get_local_ip(self):
        """Obtener IP local"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "localhost"

def run_proxy_server(proxy_instance):
    """Ejecutar el servidor proxy en un loop asyncio separado"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(proxy_instance.start_proxy_server())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error(f"Error en servidor proxy: {e}")
    finally:
        loop.close()

# =========================
# Lanzamiento principal
# =========================
if __name__ == "__main__":
    proxy = DomesticProxy()
    
    # Verificar si estamos en Render
    is_render = os.environ.get('RENDER', False) or os.environ.get('PORT') is not None
    
    if is_render:
        logger.info("🚀 Iniciando en modo Render...")
        # En Render, ejecutar solo el proxy en el hilo principal
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(proxy.start_proxy_server())
            logger.info("✅ Proxy iniciado. Ejecutando loop...")
            loop.run_forever()
        except KeyboardInterrupt:
            logger.info("🛑 Deteniendo proxy...")
        except Exception as e:
            logger.error(f"❌ Error: {e}")
        finally:
            loop.close()
    else:
        # Desarrollo local: ambos servicios
        logger.info("🚀 Iniciando servidor proxy en hilo separado...")
        proxy_thread = threading.Thread(target=run_proxy_server, args=(proxy,), daemon=True)
        proxy_thread.start()
        
        # Esperar un poco a que el proxy se inicialice
        time.sleep(2)
        
        # Iniciar dashboard web en el hilo principal
        logger.info("🌐 Iniciando dashboard web...")
        proxy.start_web_dashboard()
