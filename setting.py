# setting.py
import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent

# Obtener puerto de Render si existe
RENDER_PORT = os.environ.get('PORT', '10000')

DEFAULT_CONFIG = {
    # ===== CONFIGURACIÓN DE PUERTOS =====
    "proxy_host": "0.0.0.0",
    "proxy_port": 8080,  # Puerto del proxy HTTP
    "web_host": "0.0.0.0",
    "web_port": int(RENDER_PORT),  # Dashboard usa puerto de Render
    
    # ===== CONFIGURACIÓN DEL DASHBOARD =====
    "dashboard_domain": "proxy-familiar.onrender.com",
    "dashboard_title": "Proxy Familiar - Control Parental",
    
    # ===== CONFIGURACIÓN DE SEGURIDAD =====
    "security": {
        "require_auth": True,
        "session_timeout": 3600,
        "max_login_attempts": 3,
        "lockout_time": 900
    },
    
    # ===== BASE DE DATOS =====
    "database_url": f"sqlite:///{BASE_DIR}/data/proxy.db",
    
    # ===== CACHE =====
    "cache_enabled": True,
    "cache_size": 1000,
    "cache_ttl": 3600,
    
    # ===== FILTRADO =====
    "blocking_enabled": True,
    "youtube_blocking": True,
    "aggressive_filtering": True,
    "block_trackers": True,
    
    # ===== LOGGING =====
    "log_level": "INFO",
    
    # ===== CERTIFICADOS SSL =====
    "cert_dir": str(BASE_DIR / "config" / "certs"),
    
    # ===== LISTAS DE BLOQUEO EXTERNAS =====
    "block_lists": {
        # Anuncios generales
        "easylist": "https://easylist.to/easylist/easylist.txt",
        "easyprivacy": "https://easylist.to/easylist/easyprivacy.txt",
        "adguard_base": "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/base.txt",
        
        # Anuncios de YouTube
        "youtube_ads": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/youtube.txt",
        
        # Trackers
        "adguard_tracking": "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt",
        
        # Malware
        "malware_hosts": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        
        # Annoyances
        "adguard_annoyances": "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/AnnoyancesFilter/sections/annoyances.txt"
    },

    # ===== WHITELIST (DOMINIOS PERMITIDOS) =====
    "whitelist": [
        # Microsoft Updates
        "update.microsoft.com",
        "windowsupdate.microsoft.com",
        "microsoft.com",
        
        # YouTube esencial
        "youtube.com",
        "www.youtube.com",
        "youtu.be",
        "googlevideo.com",
        "ytimg.com",
        "ggpht.com",
        "gvt1.com",
        "edgedl.me.gvt1.com",
        
        # Google esencial
        "google.com",
        "www.google.com",
        "gstatic.com",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "googleusercontent.com",
        
        # DNS y conectividad
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        
        # Sistema operativo
        "apple.com",
        "apps.apple.com",
        "android.com",
        "play.google.com",
        
        # Educación
        "github.com",
        "stackoverflow.com",
        "wikipedia.org",
        
        # Correo
        "gmail.com",
        "outlook.com",
        "live.com",
        
        # Nube
        "drive.google.com",
        "dropbox.com",
        "onedrive.live.com"
    ],
    
    # ===== BLACKLIST (DOMINIOS BLOQUEADOS) =====
    "blacklist": [
        # Anuncios de Google/YouTube
        "googleads.g.doubleclick.net",
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "adservice.google.com",
        "ads.youtube.com",
        "videoads.google.com",
        "pagead2.googlesyndication.com",
        "tpc.googlesyndication.com",
        "2mdn.net",
        "googletagservices.com",
        "googletagmanager.com",
        
        # Anuncios de Facebook
        "connect.facebook.net",
        "facebook.com",
        "www.facebook.com",
        "fbcdn.net",
        "staticxx.facebook.com",
        "static.xx.fbcdn.net",
        
        # Anuncios de TikTok
        "ads.tiktok.com",
        "analytics.tiktok.com",
        "log-upload.tiktok.com",
        "mon-va.tiktok.com",
        
        # Twitter/X
        "twitter.com",
        "www.twitter.com",
        "twimg.com",
        "t.co",
        
        # Analytics y Tracking
        "google-analytics.com",
        "www.google-analytics.com",
        "analytics.google.com",
        "stats.g.doubleclick.net",
        "www-googletagmanager.l.google.com",
        
        # Redes publicitarias
        "adnxs.com",
        "adsystem.snapchat.com",
        "amazon-adsystem.com",
        "bat.bing.com",
        "c.amazon-adsystem.com",
        "securepubads.g.doubleclick.net",
        
        # Anuncios de video
        "ads.videoplaza.com",
        "youtube.com/api/stats/ads",
        "youtube.com/pagead",
        "youtube.com/ptracking",
        "youtube.com/get_midroll",
        
        # Malware y scams
        "popads.net",
        "propellerads.com",
        "push-notifications.com",
        "coin-hive.com",
        
        # Trackers de redes sociales
        "pixel.facebook.com",
        "tr.facebook.com",
        "static.ads-twitter.com",
        
        # Anuncios móviles
        "ads.mopub.com",
        "applovin.com",
        "unityads.unity3d.com",
        
        # Anuncios nativos
        "outbrain.com",
        "taboola.com",
        "revcontent.com",
        
        # YouTube ads específicos
        "youtube.com/ad_companion",
        "youtube.com/adlog",
        "youtube.com/api/stats/qoe",
        "youtube.com/generate_204",
        "youtube.com/live_chat_replay",
        "youtube.com/pagead/interaction",
        "youtube.com/pagead/lvz",
        "youtube.com/pagead/viewthroughconversion",
        "youtube.com/s/player",
        "youtube.com/youtubei/v1/log_event"
    ],
    
    # ===== USER AGENTS =====
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
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
            
            # Forzar puerto de Render si está en entorno de Render
            if os.environ.get('PORT'):
                config['web_port'] = int(os.environ.get('PORT'))
            
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

# Configuración específica para desarrollo
def is_render_environment():
    """Verificar si estamos en entorno de Render"""
    return os.environ.get('RENDER') is not None or os.environ.get('PORT') is not None

def get_proxy_url():
    """Obtener URL del proxy según el entorno"""
    config = load_config()
    if is_render_environment():
        return f"https://{config['dashboard_domain']}"
    else:
        return f"http://localhost:{config['proxy_port']}"

def get_dashboard_url():
    """Obtener URL del dashboard según el entorno"""
    config = load_config()
    if is_render_environment():
        return f"https://{config['dashboard_domain']}"
    else:
        return f"http://localhost:{config['web_port']}"
