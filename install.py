#!/usr/bin/env python3
import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd):
    """Ejecutar comando del sistema"""
    try:
        subprocess.run(cmd, shell=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error ejecutando comando: {cmd}")
        print(f"Error: {e}")
        return False

def main():
    print("🚀 Instalando Proxy Doméstico...")
    
    # Crear entorno virtual
    if not Path("venv").exists():
        print("📦 Creando entorno virtual...")
        if not run_command("python3 -m venv venv"):
            print("❌ Error creando entorno virtual")
            return
    
    # Determinar comando pip según SO
    if os.name == 'nt':  # Windows
        pip_cmd = "venv\\Scripts\\pip"
        python_cmd = "venv\\Scripts\\python"
    else:  # Linux/Mac
        pip_cmd = "venv/bin/pip"
        python_cmd = "venv/bin/python"
    
    # Actualizar pip primero
    print("🔄 Actualizando pip...")
    run_command(f"{pip_cmd} install --upgrade pip")
    
    # Lista de dependencias CORREGIDA (con comillas)
    requirements = [
        "flask==3.0.0",
        "waitress==3.0.2", 
        "werkzeug==3.0.1",
        "aiohttp==3.8.0",
        "asyncio==3.4.3",
        "aiohappyeyeballs==2.6.1",
        "aiosqlite==0.19.0",
        "pyOpenSSL==23.2.0",
        "cryptography==41.0.7",
        "pathlib==1.0.1",
        "click==8.1.7",
        "blinker==1.6.3",
        "itsdangerous==2.1.2",
        "jinja2==3.1.2",
        "markupsafe==2.1.3",
        "typing-extensions==4.8.0",
        "frozenlist==1.4.0",
        "attrs==23.1.0",
        "multidict==6.0.4",
        "yarl==1.9.2",
        "idna==3.4",
        "aiosignal==1.3.1",
        "propcache==0.2.0"
    ]
    
    # Instalar todas las dependencias de una vez (más eficiente)
    print("📚 Instalando dependencias...")
    requirements_str = " ".join(requirements)
    if run_command(f"{pip_cmd} install {requirements_str}"):
        print("✅ Todas las dependencias instaladas correctamente")
    else:
        print("❌ Error instalando dependencias, intentando una por una...")
        # Fallback: instalar una por una
        for package in requirements:
            print(f"📦 Instalando {package}...")
            if not run_command(f"{pip_cmd} install {package}"):
                print(f"⚠️  Error instalando {package}, continuando...")
    
    # Crear estructura de directorios
    print("📁 Creando estructura de directorios...")
    directories = [
        "config/certs",
        "data/block_lists", 
        "data/logs",
        "data/cache",
        "web/templates",
        "web/static"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Directorio creado: {directory}")
    
    # Crear archivos esenciales si no existen
    print("📄 Creando archivos de configuración...")
    
    # Crear setting.py si no existe
    if not Path("setting.py").exists():
        setting_content = '''# setting.py
import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent

# Configuración por defecto
DEFAULT_CONFIG = {
    "proxy_host": "0.0.0.0",
    "proxy_port": 8080,
    "web_host": "0.0.0.0", 
    "web_port": 8081,
    "dashboard_title": "Proxy Familiar",
    "blocking_enabled": True,
    "youtube_blocking": True,
    "whitelist": [
        "youtube.com", "www.youtube.com", "googlevideo.com",
        "google.com", "gstatic.com", "fonts.googleapis.com"
    ],
    "blacklist": [
        "googleads.g.doubleclick.net", "doubleclick.net",
        "googlesyndication.com", "googleadservices.com"
    ]
}

def load_config():
    """Cargar configuración"""
    return DEFAULT_CONFIG.copy()

def add_to_blacklist(domain):
    """Añadir dominio a blacklist"""
    print(f"Dominio bloqueado: {domain}")
    return DEFAULT_CONFIG.copy()

def add_to_whitelist(domain):
    """Añadir dominio a whitelist"""
    print(f"Dominio permitido: {domain}")
    return DEFAULT_CONFIG.copy()
'''
        with open("setting.py", "w", encoding="utf-8") as f:
            f.write(setting_content)
        print("✅ setting.py creado")
    
    # Crear config.json si no existe
    config_dir = Path("config")
    config_file = config_dir / "config.json"
    if not config_file.exists():
        default_config = {
            "proxy_host": "0.0.0.0",
            "proxy_port": 8080,
            "web_host": "0.0.0.0",
            "web_port": 8081,
            "dashboard_title": "Proxy Familiar - Control Parental",
            "blocking_enabled": True,
            "youtube_blocking": True,
            "aggressive_filtering": True,
            "block_trackers": True,
            "security": {
                "require_auth": True,
                "session_timeout": 3600,
                "max_login_attempts": 3,
                "lockout_time": 900
            },
            "whitelist": [
                "youtube.com", "www.youtube.com", "googlevideo.com",
                "google.com", "gstatic.com", "fonts.googleapis.com",
                "fonts.gstatic.com", "github.com", "stackoverflow.com"
            ],
            "blacklist": [
                "googleads.g.doubleclick.net", "doubleclick.net",
                "googlesyndication.com", "googleadservices.com",
                "ads.youtube.com", "pagead2.googlesyndication.com"
            ]
        }
        
        import json
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=4, ensure_ascii=False)
        print("✅ config.json creado")
    
    # Verificar instalación
    print("\n🔍 Verificando instalación...")
    test_commands = [
        f"{python_cmd} -c \"import flask; print('✅ Flask OK')\"",
        f"{python_cmd} -c \"import aiohttp; print('✅ AioHTTP OK')\"",
        f"{python_cmd} -c \"import aiosqlite; print('✅ Aiosqlite OK')\"",
        f"{python_cmd} -c \"import OpenSSL; print('✅ OpenSSL OK')\"",
        f"{python_cmd} -c \"import cryptography; print('✅ Cryptography OK')\""
    ]
    
    for cmd in test_commands:
        run_command(cmd)
    
    print("\n🎉 ¡Instalación completada!")
    print("\n📝 Para iniciar el proxy:")
    if os.name == 'nt':
        print("  venv\\Scripts\\python main.py")
    else:
        print("  source venv/bin/activate && python main.py")
        print("  o")
        print("  venv/bin/python main.py")
    
    print("\n🌐 URLs de acceso:")
    print("  Panel web:    http://localhost:8081")
    print("  Proxy HTTP:   http://localhost:8080")
    print("\n🔧 Configuración del navegador:")
    print("  Servidor: 127.0.0.1")
    print("  Puerto:   8080")
    print("\n🔐 Credenciales por defecto:")
    print("  Usuario: admin")
    print("  Contraseña: admin123")

if __name__ == "__main__":
    main()
