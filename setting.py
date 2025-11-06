# setting.py
import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent

# Obtener puerto de Render si existe
RENDER_PORT = os.environ.get('PORT', '10000')

DEFAULT_CONFIG = {
    "proxy_host": "0.0.0.0",
    "proxy_port": int(RENDER_PORT),  # Usar puerto de Render para el servicio principal
    "web_host": "0.0.0.0",
    "web_port": 8081,  # Dashboard en puerto interno
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

def save_config(config):
    """Guarda la configuración actual en el archivo config.json"""
    config_path = BASE_DIR / "config" / "config.json"
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        print(f"[INFO] Configuración guardada en {config_path}")
        return True
    except Exception as e:
        print(f"[ERROR] No se pudo guardar la configuración: {e}")
        return False

def load_config():
    """Cargar configuración desde archivo o usar valores por defecto"""
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
            
            # Combinar configuraciones manteniendo los valores por defecto para claves faltantes
            config = DEFAULT_CONFIG.copy()
            
            # Merge profundo para diccionarios anidados
            def deep_update(default, user):
                for key, value in user.items():
                    if isinstance(value, dict) and key in default and isinstance(default[key], dict):
                        deep_update(default[key], value)
                    else:
                        default[key] = value
            
            deep_update(config, user_config)
            
        else:
            config = DEFAULT_CONFIG.copy()
            # Guardar configuración por defecto
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            print(f"[INFO] Configuración por defecto creada en {config_path}")

    except (json.JSONDecodeError, OSError) as e:
        print(f"[WARN] Error al cargar configuración: {e}. Usando valores por defecto.")
        config = DEFAULT_CONFIG.copy()

    # Asegurar que el directorio de certificados existe
    cert_dir = config.get('cert_dir', '')
    if cert_dir:
        Path(cert_dir).mkdir(parents=True, exist_ok=True)

    return config

def add_to_blacklist(domain):
    """Añadir dominio a la blacklist y guardar configuración"""
    config = load_config()
    if domain not in config['blacklist']:
        config['blacklist'].append(domain)
        save_config(config)
        print(f"[INFO] Dominio añadido a blacklist: {domain}")
    return config

def add_to_whitelist(domain):
    """Añadir dominio a la whitelist y guardar configuración"""
    config = load_config()
    if domain not in config['whitelist']:
        config['whitelist'].append(domain)
        save_config(config)
        print(f"[INFO] Dominio añadido a whitelist: {domain}")
    return config

def remove_from_blacklist(domain):
    """Remover dominio de la blacklist"""
    config = load_config()
    if domain in config['blacklist']:
        config['blacklist'].remove(domain)
        save_config(config)
        print(f"[INFO] Dominio removido de blacklist: {domain}")
    return config

def remove_from_whitelist(domain):
    """Remover dominio de la whitelist"""
    config = load_config()
    if domain in config['whitelist']:
        config['whitelist'].remove(domain)
        save_config(config)
        print(f"[INFO] Dominio removido de whitelist: {domain}")
    return config
