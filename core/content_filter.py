# core/content_filter.py
import re
import aiohttp
import asyncio
from pathlib import Path
from typing import Set, List, Pattern, Dict, Optional, Tuple
import logging
import time
from urllib.parse import urlparse
import hashlib
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

@dataclass
class FilterStats:
    """Estadísticas de filtrado en tiempo real"""
    total_requests: int = 0
    blocked_requests: int = 0
    youtube_ads_blocked: int = 0
    whitelist_hits: int = 0
    last_updated: float = 0

class ContentFilter:
    """
    Sistema avanzado de filtrado de contenido con optimizaciones de rendimiento.
    Especializado en bloquear anuncios de YouTube sin afectar la funcionalidad.
    """

    def __init__(self, config: Dict):
        self.config = config
        self.blocked_domains: Set[str] = set()
        self.blocked_patterns: List[Pattern] = []
        self.whitelist: Set[str] = set(config.get('whitelist', []))
        self.blacklist: Set[str] = set(config.get('blacklist', []))
        
        # Caché para decisiones de bloqueo (TTL: 5 minutos)
        self._block_cache: Dict[str, Tuple[bool, float]] = {}
        self._cache_ttl = 300  # 5 minutos
        
        # Estadísticas
        self.stats = FilterStats()
        self._stats_lock = asyncio.Lock()
        
        # Patrones optimizados para YouTube ADS (no funcionalidad)
        self.youtube_ad_patterns = self._init_youtube_patterns()
        
        # Executor para operaciones bloqueantes
        self._thread_pool = ThreadPoolExecutor(max_workers=2)
        
        # Flags de estado
        self._initialized = False
        self._load_task: Optional[asyncio.Task] = None
        
        # DOMINIOS ESENCIALES DE YOUTUBE QUE NUNCA DEBEN BLOQUEARSE
        self.youtube_essential_domains = {
            'youtube.com', 'www.youtube.com', 'm.youtube.com',
            'youtu.be', 'googlevideo.com', 'ytimg.com', 
            'ggpht.com', 'googleapis.com', 'google.com',
            'gstatic.com', 'fonts.gstatic.com', 'ajax.googleapis.com'
        }
        
        logger.info("🚀 ContentFilter inicializado")

    def _init_youtube_patterns(self) -> Dict[str, Pattern]:
        """Inicializar patrones optimizados para anuncios de YouTube"""
        return {
            # URLs específicas de anuncios de YouTube
            # URLs específicas de anuncios de YouTube - VERSIÓN EXPANDIDA
                'ad_urls': re.compile(
                    r'(?:'
                    # Dominios de Google Ads
                    r'pagead2\.googlesyndication\.com|'
                    r'ads\.youtube\.com|'
                    r'doubleclick\.net|'
                    r'googleads\.g\.doubleclick\.net|'
                    r'partnerad\.g\.doubleclick\.net|'
                    r'ad\.doubleclick\.net|'
                    r'fundingchoicesmessages\.google\.com|'
                    r'googleadservices\.com|'
                    r'tpc\.googlesyndication\.com|'
                    r'securepubads\.g\.doubleclick\.net|'
                    r'adservice\.google\.com|'
                    r'adservice\.google\.[a-z]{2,3}|'
                    r'googlesyndication\.com|'
                    r'google-analytics\.com|'
                    
                    # Más dominios de anuncios comunes
                    r'2mdn\.net|'
                    r'gstatic\.com/cv/js/sender/|'
                    r'www-google-analytics\.l\.google\.com|'
                    r'pagead-googlehosted\.l\.google\.com|'
                    r'partnerad\.l\.google\.com|'
                    r'afs\.googleadservices\.com|'
                    r'www\.googletagservices\.com|'
                    r'www\.google\.com/pagead/|'
                    r'google\.com/pagead/|'
                    r's0\.2mdn\.net|'
                    r'static\.doubleclick\.net|'
                    
                    # Redes publicitarias de terceros
                    r'ad\.nend\.net|'
                    r'adsystem\.com|'
                    r'serving-sys\.com|'
                    r'casalemedia\.com|'
                    r'adtech\.de|'
                    r'advertising\.com|'
                    r'rubiconproject\.com|'
                    r'appnexus\.com|'
                    r'openx\.net|'
                    r'pubmatic\.com|'
                    r'criteo\.com|'
                    r'moatads\.com|'
                    r'scorecardresearch\.com|'
                    r'quantserve\.com|'
                    r'outbrain\.com|'
                    r'taboola\.com|'
                    
                    # Trackers y analytics
                    r'googletagmanager\.com|'
                    r'googleoptimize\.com|'
                    r'hotjar\.com|'
                    r'crazyegg\.com|'
                    r'clicktale\.net|'
                    
                    # CDNs de anuncios
                    r'cdn\.doubleverify\.com|'
                    r'cdn\.moatads\.com|'
                    r'ads\.rubiconproject\.com|'
                    
                    # Parámetros de URL
                    r'[\?&]adformat=|\bads\b|'
                    r'[\?&]ad_type=|\bad_type\b|'
                    r'[\?&]ad_break=|\bad_break\b|'
                    r'[\?&]ad_session=|\bad_session\b|'
                    r'[\?&]ad_channel=|\bad_channel\b|'
                    r'[\?&]ad_position=|\bad_position\b|'
                    r'[\?&]ad_network=|\bad_network\b|'
                    
                    # YouTube específico
                    r'videoplayback\?.*[&?]ctier=|'
                    r'videoplayback\?.*[&?]oad=|'
                    r'videoplayback\?.*[&?]ovad=|'
                    r'videoplayback\?.*[&?]of=|'
                    r'youtube\.com/api/stats/ads|'
                    r'youtube\.com/pagead/|'
                    r'youtube\.com/ptracking|'
                    r'youtube\.com/get_midroll|'
                    
                    # Palabras clave en URL
                    r'/ads/|'
                    r'/ad/|'
                    r'/banner/|'
                    r'/promo/|'
                    r'/sponsor/|'
                    r'/tracking/|'
                    r'/analytics/|'
                    r'/beacon/|'
                    r'/pixel/|'
                    r'/impression/|'
                    r'/click/|'
                    r'/delivery/|'
                    r'/log_event|'
                    r'/log_interaction|'
                    
                    # Subdominios comunes de ads
                    r'ads\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}|'
                    r'ad\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}|'
                    r'adserver\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}|'
                    r'advert\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}|'
                    r'banner\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}|'
                    r'tracker\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}|'
                    r'tracking\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}|'
                    r'analytics\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}'
                    r')', 
                    re.IGNORECASE
                ),
                
                # Headers de anuncios - EXPANDIDO
                'ad_headers': re.compile(
                    r'(?:'
                    r'ads|advert|doubleclick|googleads|googlesyndication|'
                    r'ad-server|adserver|ad-network|adnetwork|'
                    r'ad-content|adcontent|ad-wrapper|adwrapper|'
                    r'ad-frame|adframe|ad-unit|adunit|'
                    r'ad-tag|adtag|ad-slot|adslot|'
                    r'ad-campaign|adcampaign|ad-placement|adplacement|'
                    r'ad-request|adrequest|ad-response|adresponse|'
                    r'ad-impression|adimpression|ad-click|adclick|'
                    r'ad-view|adview|ad-load|adload|'
                    r'ad-beacon|adbeacon|ad-pixel|adpixel|'
                    r'ad-tracking|adtracking|ad-analytics|adanalytics|'
                    r'ad-delivery|addelivery|ad-serving|adserving|'
                    r'ad-bid|adbid|ad-auction|adauction|'
                    r'ad-exchange|adexchange|ad-marketplace|admarketplace|'
                    r'ad-mediation|admediation|ad-optimization|adoptimization|'
                    r'ad-targeting|adtargeting|ad-segment|adsegment|'
                    r'ad-profile|adprofile|ad-audience|adaudience|'
                    r'ad-revenue|adrevenue|ad-monetization|admonetization|'
                    r'ad-verification|adverification|ad-measurement|admeasurement|'
                    r'youtube-ad|youtubead|yt-ad|ytad|'
                    r'video-ad|videoad|pre-roll|preroll|'
                    r'mid-roll|midroll|post-roll|postroll|'
                    r'banner-ad|bannerad|popup-ad|popupad|'
                    r'interstitial-ad|interstitialad|native-ad|nativead|'
                    r'sponsored-content|sponsoredcontent|promoted-content|promotedcontent'
                    r')',
                    re.IGNORECASE
                ),
                
                # Scripts de anuncios en HTML - EXPANDIDO
                'ad_scripts': re.compile(
                    r'(?:'
                    r'adsystem|googleadservices|doubleclick\.net|googlesyndication|'
                    r'adserver|adserver\.|adserver-|'
                    r'adtech|adtech\.|adtech-|'
                    r'appnexus|appnexus\.|appnexus-|'
                    r'rubiconproject|rubiconproject\.|rubiconproject-|'
                    r'openx|openx\.|openx-|'
                    r'pubmatic|pubmatic\.|pubmatic-|'
                    r'criteo|criteo\.|criteo-|'
                    r'moatads|moatads\.|moatads-|'
                    r'scorecardresearch|scorecardresearch\.|scorecardresearch-|'
                    r'quantserve|quantserve\.|quantserve-|'
                    r'outbrain|outbrain\.|outbrain-|'
                    r'taboola|taboola\.|taboola-|'
                    r'googletagmanager|googletagmanager\.|googletagmanager-|'
                    r'googleoptimize|googleoptimize\.|googleoptimize-|'
                    r'hotjar|hotjar\.|hotjar-|'
                    r'crazyegg|crazyegg\.|crazyegg-|'
                    r'clicktale|clicktale\.|clicktale-|'
                    r'ad\.js|ads\.js|adscript|ad-script|'
                    r'banner\.js|banners\.js|bannerscript|banner-script|'
                    r'tracker\.js|trackers\.js|trackerscript|tracker-script|'
                    r'analytics\.js|analyticsscript|analytics-script|'
                    r'beacon\.js|beaconscript|beacon-script|'
                    r'pixel\.js|pixelscript|pixel-script|'
                    r'youtubeads|youtube-ads|ytads|yt-ads|'
                    r'videoads|video-ads|videoads|video-ads'
                    r')',
                    re.IGNORECASE
                ),
                
                # Elementos DOM de anuncios de YouTube - EXPANDIDO
                'ad_elements': re.compile(
                    r'(?:'
                    # Clases específicas de YouTube
                    r'ytp-ad-|'
                    r'ytd-ad-|'
                    r'ytd-promoted-|'
                    r'ytd-compact-promoted-|'
                    r'ytd-display-ad-|'
                    r'ytd-in-feed-ad-|'
                    r'ytd-action-companion-ad-|'
                    r'ytd-banner-promo-|'
                    
                    # Clases generales de anuncios
                    r'ad-container|'
                    r'ad-div|'
                    r'ad-overlay|'
                    r'ad-wrapper|'
                    r'ad-frame|'
                    r'ad-unit|'
                    r'ad-slot|'
                    r'ad-placement|'
                    r'ad-content|'
                    r'ad-body|'
                    r'ad-header|'
                    r'ad-footer|'
                    r'ad-sidebar|'
                    r'ad-top|'
                    r'ad-bottom|'
                    r'ad-left|'
                    r'ad-right|'
                    r'ad-center|'
                    r'ad-middle|'
                    r'ad-popup|'
                    r'ad-modal|'
                    r'ad-lightbox|'
                    r'ad-sticky|'
                    r'ad-fixed|'
                    r'ad-floating|'
                    r'ad-expandable|'
                    r'ad-collapsible|'
                    r'ad-rotating|'
                    r'ad-sliding|'
                    r'ad-animated|'
                    r'ad-interactive|'
                    
                    # IDs de anuncios
                    r'player-ads|'
                    r'video-ads|'
                    r'banner-ad|'
                    r'sidebar-ad|'
                    r'header-ad|'
                    r'footer-ad|'
                    r'popup-ad|'
                    r'overlay-ad|'
                    r'interstitial-ad|'
                    r'native-ad|'
                    r'sponsored-ad|'
                    r'promoted-ad|'
                    
                    # Atributos de datos
                    r'data-ad-|'
                    r'data-ads-|'
                    r'data-adunit|'
                    r'data-adslot|'
                    r'data-ad-client|'
                    r'data-ad-format|'
                    r'data-ad-type|'
                    r'data-ad-network|'
                    r'data-ad-position|'
                    r'data-ad-targeting|'
                    
                    # YouTube específico
                    r'companion-ad|'
                    r'invideo-ad|'
                    r'instream-ad|'
                    r'outstream-ad|'
                    r'midroll-ad|'
                    r'preroll-ad|'
                    r'postroll-ad|'
                    r'brand-ad|'
                    r'product-ad|'
                    r'shopping-ad'
                    r')',
                    re.IGNORECASE
                ),
                
                # Parámetros de URL específicos de ads - EXPANDIDO
                'ad_params': re.compile(
                    r'[?&](?:'
                    # Parámetros de Google Ads
                    r'gclid=|'
                    r'fbclid=|'
                    r'utm_campaign=|'
                    r'utm_source=|'
                    r'utm_medium=|'
                    r'utm_term=|'
                    r'utm_content=|'
                    r'utm_id=|'
                    r'ad_type=|'
                    r'adformat=|'
                    r'ad_channel=|'
                    r'ad_position=|'
                    r'ad_network=|'
                    r'ad_target=|'
                    r'ad_keyword=|'
                    r'ad_group=|'
                    r'ad_campaign=|'
                    r'ad_creative=|'
                    r'ad_placement=|'
                    r'ad_slot=|'
                    r'ad_unit=|'
                    r'ad_break=|'
                    r'ad_session=|'
                    r'ad_impression=|'
                    r'ad_click=|'
                    r'ad_view=|'
                    r'ad_load=|'
                    r'ad_bid=|'
                    r'ad_auction=|'
                    r'ad_exchange=|'
                    r'ad_mediation=|'
                    r'ad_optimization=|'
                    r'ad_targeting=|'
                    r'ad_segment=|'
                    r'ad_profile=|'
                    r'ad_audience=|'
                    r'ad_revenue=|'
                    r'ad_monetization=|'
                    r'ad_verification=|'
                    r'ad_measurement=|'
                    
                    # YouTube específico
                    r'ctier=|'
                    r'oad=|'
                    r'ovad=|'
                    r'of=|'
                    r'adformat=|'
                    r'instream=|'
                    r'companion=|'
                    r'midroll=|'
                    r'preroll=|'
                    r'postroll=|'
                    
                    # Parámetros de tracking
                    r'tracking_id=|'
                    r'tracking_code=|'
                    r'tracking_key=|'
                    r'tracking_source=|'
                    r'tracking_medium=|'
                    r'tracking_campaign=|'
                    r'tracking_term=|'
                    r'tracking_content=|'
                    r'clickid=|'
                    r'affiliate_id=|'
                    r'partner_id=|'
                    r'ref_id=|'
                    r'sub_id=|'
                    r'subid=|'
                    
                    # Analytics
                    r'analytics_id=|'
                    r'analytics_key=|'
                    r'analytics_source=|'
                    r'beacon_id=|'
                    r'pixel_id=|'
                    r'impression_id=|'
                    r'view_id=|'
                    r'session_id=|'
                    r'user_id=|'
                    r'visitor_id=|'
                    r'customer_id=|'
                    r'client_id=|'
                    r'campaign_id=|'
                    r'creative_id=|'
                    r'placement_id=|'
                    r'site_id=|'
                    r'zone_id=|'
                    r'banner_id=|'
                    r'ad_id=|'
                    r'adid='
                    r')',
                    re.IGNORECASE
                ),
                
                # Patrones de video ads específicos de YouTube - EXPANDIDO
                'video_ads': re.compile(
                    r'(?:'
                    # YouTube video ads
                    r'/videoplayback\?.*[&?]ctier=|'
                    r'/videoplayback\?.*[&?]oad=|'
                    r'/videoplayback\?.*[&?]ovad=|'
                    r'/videoplayback\?.*[&?]of=|'
                    r'/get_midroll_|'
                    r'/get_preroll_|'
                    r'/get_postroll_|'
                    r'/ptracking\?|'
                    r'/pagead/|'
                    r'/log_event\?|'
                    r'/log_interaction\?|'
                    r'/ad_event\?|'
                    r'/ad_interaction\?|'
                    r'/ad_impression\?|'
                    r'/ad_click\?|'
                    r'/ad_view\?|'
                    r'/ad_load\?|'
                    r'/ad_break\?|'
                    r'/ad_session\?|'
                    r'/ad_request\?|'
                    r'/ad_response\?|'
                    r'/ad_delivery\?|'
                    r'/ad_serving\?|'
                    r'/ad_targeting\?|'
                    r'/ad_placement\?|'
                    r'/ad_unit\?|'
                    r'/ad_slot\?|'
                    r'/ad_campaign\?|'
                    r'/ad_creative\?|'
                    r'/ad_network\?|'
                    r'/ad_exchange\?|'
                    r'/ad_mediation\?|'
                    r'/ad_auction\?|'
                    r'/ad_bid\?|'
                    r'/ad_revenue\?|'
                    r'/ad_monetization\?|'
                    r'/ad_verification\?|'
                    r'/ad_measurement\?|'
                    
                    # Paths comunes de ads
                    r'/ads/|'
                    r'/ad/|'
                    r'/banner/|'
                    r'/promo/|'
                    r'/sponsor/|'
                    r'/tracking/|'
                    r'/analytics/|'
                    r'/beacon/|'
                    r'/pixel/|'
                    r'/impression/|'
                    r'/click/|'
                    r'/delivery/|'
                    r'/serving/|'
                    r'/targeting/|'
                    r'/placement/|'
                    r'/unit/|'
                    r'/slot/|'
                    r'/campaign/|'
                    r'/creative/|'
                    r'/network/|'
                    r'/exchange/|'
                    r'/mediation/|'
                    r'/auction/|'
                    r'/bid/|'
                    r'/revenue/|'
                    r'/monetization/|'
                    r'/verification/|'
                    r'/measurement/|'
                    
                    # YouTube API endpoints de ads
                    r'youtube\.com/api/stats/ads|'
                    r'youtube\.com/api/stats/qoe|'
                    r'youtube\.com/api/stats/playback|'
                    r'youtube\.com/api/stats/watchtime|'
                    r'youtube\.com/api/stats/atr|'
                    r'youtube\.com/api/stats/|'
                    
                    # Otros patrones
                    r'/vast|'
                    r'/vmap|'
                    r'/vpaid|'
                    r'/adstream|'
                    r'/adflow|'
                    r'/adpath|'
                    r'/adroute|'
                    r'/adtrack|'
                    r'/advertise|'
                    r'/advertising|'
                    r'/monetize|'
                    r'/monetization|'
                    r'/sponsorship|'
                    r'/promotion|'
                    r'/affiliate|'
                    r'/partner|'
                    r'/revshare|'
                    r'/revenue'
                    r')',
                    re.IGNORECASE
            )
        }

    async def initialize(self) -> None:
        """Inicialización asíncrona del filtro"""
        if self._initialized:
            return
            
        self._load_task = asyncio.create_task(self._load_all_block_lists())
        await self._load_task
        self._initialized = True
        logger.info("✅ ContentFilter completamente inicializado")

    async def _load_all_block_lists(self) -> None:
        """Cargar todas las listas de bloqueo en paralelo"""
        block_list_dir = Path("data/block_lists")
        block_list_dir.mkdir(parents=True, exist_ok=True)
        
        # Listas optimizadas para anuncios (no funcionalidad)
        block_lists = [
            # Lista específica de anuncios de YouTube
            ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/youtube.txt", "youtube_ads.txt"),
            # Lista general de anuncios
            ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "steven_black.txt"),
            # Lista de trackers
            ("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt", "tracking.txt"),
        ]
        
        # Cargar listas en paralelo
        tasks = []
        for url, filename in block_lists:
            task = asyncio.create_task(self._load_single_block_list(url, filename))
            tasks.append(task)
        
        # Esperar a que todas se carguen
        await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info(f"📊 Filtro cargado: {len(self.blocked_domains)} dominios, {len(self.blocked_patterns)} patrones")

    async def _load_single_block_list(self, url: str, filename: str) -> None:
        """Cargar una sola lista de bloqueo con manejo de errores"""
        try:
            filepath = Path("data/block_lists") / filename
            
            # Descargar si no existe o es muy viejo (>7 días)
            if not filepath.exists() or self._is_file_old(filepath):
                await self._download_block_list(url, filepath)
            
            # Parsear lista
            count = await self._parse_block_list(filepath)
            logger.info(f"📋 {count} reglas cargadas de {filename}")
            
        except Exception as e:
            logger.error(f"❌ Error cargando lista {filename}: {e}")

    def _is_file_old(self, filepath: Path, max_age_days: int = 7) -> bool:
        """Verificar si un archivo es más viejo que max_age_days"""
        if not filepath.exists():
            return True
        
        file_age = time.time() - filepath.stat().st_mtime
        return file_age > (max_age_days * 24 * 3600)

    async def _download_block_list(self, url: str, filepath: Path) -> None:
        """Descargar lista de bloqueo con timeout y reintentos"""
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for attempt in range(3):
                try:
                    async with session.get(url) as response:
                        if response.status == 200:
                            content = await response.text()
                            # Guardar con encoding UTF-8
                            filepath.write_text(content, encoding='utf-8')
                            logger.info(f"📥 Lista descargada: {filepath.name}")
                            return
                        else:
                            logger.warning(f"⚠️  HTTP {response.status} para {url}")
                            
                except asyncio.TimeoutError:
                    logger.warning(f"⏰ Timeout en intento {attempt + 1} para {url}")
                except Exception as e:
                    logger.warning(f"⚠️  Error en intento {attempt + 1} para {url}: {e}")
                
                if attempt < 2:
                    await asyncio.sleep(2 ** attempt)  # Backoff exponencial
            
            logger.error(f"❌ Falló la descarga de {url} después de 3 intentos")

    async def _parse_block_list(self, filepath: Path) -> int:
        """Parsear archivo de lista de bloqueo de forma eficiente"""
        count = 0
        filename = filepath.name
        
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            lines = content.splitlines()
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                
                # Saltar rápido comentarios y líneas vacías
                if not line or line[0] in ('!', '#'):
                    continue
                
                # Procesar línea
                added = await self._process_line(line, filename)
                if added:
                    count += 1
                    
                # Yield cada 1000 líneas para no bloquear el event loop
                if line_num % 1000 == 0:
                    await asyncio.sleep(0)
            
            return count
            
        except Exception as e:
            logger.error(f"❌ Error parseando {filename}: {e}")
            return count

    async def _process_line(self, line: str, filename: str) -> bool:
        """Procesar una línea individual de lista de bloqueo"""
        try:
            # FORMATO 1: Archivos hosts (127.0.0.1 dominio.com)
            if re.match(r'^\d+\.\d+\.\d+\.\d+\s+', line):
                parts = line.split()
                if len(parts) >= 2:
                    domain = parts[1].strip()
                    return await self._add_domain_if_valid(domain)
            
            # FORMATO 2: Reglas AdBlock (||dominio.com^)
            elif line.startswith('||') and line.endswith('^'):
                domain = line[2:-1].strip()
                return await self._add_domain_and_pattern(domain)
            
            # FORMATO 3: Reglas de elementos (##selector)
            elif line.startswith('##'):
                selector = line[2:].strip()
                return await self._add_css_selector(selector)
            
            # FORMATO 4: Reglas de excepción (@@||dominio.com^)
            elif line.startswith('@@||') and line.endswith('^'):
                domain = line[4:-1].strip()
                self.whitelist.add(domain)
                return True
            
            # FORMATO 5: Dominios simples
            elif self._is_simple_domain(line):
                return await self._add_domain_if_valid(line)
            
            # FORMATO 6: Líneas con palabras clave de anuncios
            elif self._contains_ad_keywords(line):
                domain_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', line)
                if domain_match:
                    return await self._add_domain_if_valid(domain_match.group(1))
            
            return False
            
        except Exception as e:
            logger.debug(f"Error procesando línea '{line}': {e}")
            return False

    async def _add_domain_if_valid(self, domain: str) -> bool:
        """Añadir dominio si es válido y no está en whitelist"""
        if not domain or not self._is_valid_domain(domain):
            return False
        
        if self._is_whitelisted_domain(domain):
            return False
        
        self.blocked_domains.add(domain)
        return True

    async def _add_domain_and_pattern(self, domain: str) -> bool:
        """Añadir dominio y patrón correspondiente"""
        if not await self._add_domain_if_valid(domain):
            return False
        
        # Crear patrón regex eficiente para el dominio
        pattern = re.compile(
            rf'(^|\.){re.escape(domain)}$',
            re.IGNORECASE
        )
        self.blocked_patterns.append(pattern)
        return True

    async def _add_css_selector(self, selector: str) -> bool:
        """Añadir selector CSS como patrón regex"""
        pattern = self._css_selector_to_regex(selector)
        if pattern:
            self.blocked_patterns.append(pattern)
            return True
        return False

    def _is_simple_domain(self, text: str) -> bool:
        """Verificar si el texto es un dominio simple"""
        return bool(re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', text))

    def _contains_ad_keywords(self, text: str) -> bool:
        """Verificar si el texto contiene palabras clave de anuncios"""
        keywords = {'ad', 'ads', 'banner', 'track', 'analytics', 'doubleclick'}
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in keywords)

    def _is_valid_domain(self, domain: str) -> bool:
        """Verificar si un dominio es válido para bloqueo"""
        # NUNCA bloquear dominios esenciales de YouTube
        if domain in self.youtube_essential_domains:
            return False
        
        # Verificar si es subdominio de esencial
        for essential in self.youtube_essential_domains:
            if domain.endswith('.' + essential):
                return False
        
        return True

    def _is_whitelisted_domain(self, domain: str) -> bool:
        """Verificar si un dominio está en la whitelist"""
        if domain in self.whitelist:
            return True
        
        # Verificar subdominios de whitelist
        return any(
            domain == allowed or domain.endswith('.' + allowed)
            for allowed in self.whitelist
        )

    def _css_selector_to_regex(self, selector: str) -> Optional[Pattern]:
        """Convertir selector CSS a patrón regex optimizado"""
        try:
            selector = selector.strip()
            if not selector:
                return None
            
            # Mapeo de selectores comunes a regex precompilados
            common_selectors = {
                # YouTube ads específicos
                '.ytp-ad-module': r'<[^>]*class=[^>]*ytp-ad-module[^>]*>',
                '.ytp-ad-overlay-container': r'<[^>]*class=[^>]*ytp-ad-overlay-container[^>]*>',
                '.ytp-ad-player-overlay': r'<[^>]*class=[^>]*ytp-ad-player-overlay[^>]*>',
                '.ytp-ad-progress': r'<[^>]*class=[^>]*ytp-ad-progress[^>]*>',
                '.ytp-ad-skip-button': r'<[^>]*class=[^>]*ytp-ad-skip-button[^>]*>',
                '.ytp-ad-text': r'<[^>]*class=[^>]*ytp-ad-text[^>]*>',
                '.video-ads': r'<[^>]*class=[^>]*video-ads[^>]*>',
                '#player-ads': r'<[^>]*id=[^>]*player-ads[^>]*>',
                '.ad-container': r'<[^>]*class=[^>]*ad-container[^>]*>',
                '.ad-div': r'<[^>]*class=[^>]*ad-div[^>]*>',
                '.ad-overlay': r'<[^>]*class=[^>]*ad-overlay[^>]*>',
                
                # Selectores genéricos
                '.ad': r'<[^>]*class=[^>]*\bad\b[^>]*>',
                '.ads': r'<[^>]*class=[^>]*\bads\b[^>]*>',
                '[class*="ad"]': r'<[^>]*class=[^>]*ad[^>]*>',
            }
            
            # Buscar selector conocido
            for css_pattern, regex_pattern in common_selectors.items():
                if css_pattern in selector:
                    return re.compile(regex_pattern, re.IGNORECASE)
            
            # Selector de clase genérico
            if selector.startswith('.'):
                class_name = re.escape(selector[1:])
                return re.compile(
                    rf'<[^>]*class=[^>]*{class_name}[^>]*>',
                    re.IGNORECASE
                )
            
            # Selector de ID genérico
            elif selector.startswith('#'):
                id_name = re.escape(selector[1:])
                return re.compile(
                    rf'<[^>]*id=[^>]*{id_name}[^>]*>',
                    re.IGNORECASE
                )
            
            return None
            
        except Exception as e:
            logger.debug(f"Error convirtiendo selector CSS {selector}: {e}")
            return None

    def _get_cache_key(self, domain: str, url: str) -> str:
        """Generar clave de caché única"""
        key_data = f"{domain}:{url}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _clean_cache(self) -> None:
        """Limpiar caché expirado"""
        now = time.time()
        expired_keys = [
            key for key, (_, expiry) in self._block_cache.items()
            if expiry < now
        ]
        for key in expired_keys:
            del self._block_cache[key]

    async def should_block(self, domain: str, url: str, headers: dict) -> bool:
        """Determinar si bloquear una petición de forma optimizada"""
        async with self._stats_lock:
            self.stats.total_requests += 1
            self.stats.last_updated = time.time()

        # Verificar configuración
        if not self.config.get('blocking_enabled', True):
            return False

        # Verificar caché primero
        cache_key = self._get_cache_key(domain, url)
        now = time.time()
        
        if cache_key in self._block_cache:
            cached_result, expiry = self._block_cache[cache_key]
            if expiry > now:
                if cached_result:
                    async with self._stats_lock:
                        self.stats.blocked_requests += 1
                return cached_result
            else:
                del self._block_cache[cache_key]

        # Limpiar caché periódicamente
        if len(self._block_cache) > 1000:
            self._clean_cache()

        # Proceso de decisión de bloqueo
        should_block = await self._evaluate_blocking(domain, url, headers)
        
        # Actualizar caché
        self._block_cache[cache_key] = (should_block, now + self._cache_ttl)
        
        if should_block:
            async with self._stats_lock:
                self.stats.blocked_requests += 1
        
        return should_block

    async def _evaluate_blocking(self, domain: str, url: str, headers: dict) -> bool:
        """Evaluar si se debe bloquear la petición"""
        # 1. Verificar lista blanca
        if self._is_whitelisted(domain, url):
            async with self._stats_lock:
                self.stats.whitelist_hits += 1
            return False

        # 2. Verificar lista negra manual
        if domain in self.blacklist:
            logger.debug(f"🚫 Bloqueado por blacklist: {domain}")
            return True

        # 3. Verificar dominios bloqueados
        if domain in self.blocked_domains:
            logger.debug(f"🚫 Bloqueado por lista: {domain}")
            return True

        # 4. Verificar patrones de URL
        for pattern in self.blocked_patterns:
            if pattern.search(url):
                logger.debug(f"🚫 Bloqueado por patrón: {domain}")
                return True

        # 5. Filtrado específico para YouTube ADS
        if self.config.get('youtube_blocking', True) and self._is_youtube_related(domain):
            if self._is_youtube_ad(domain, url, headers):
                async with self._stats_lock:
                    self.stats.youtube_ads_blocked += 1
                logger.debug(f"🎯 Bloqueado anuncio YouTube: {domain}")
                return True

        return False

    def _is_whitelisted(self, domain: str, url: str) -> bool:
        """Verificar si está en la lista blanca de forma optimizada"""
        if domain in self.whitelist:
            return True
        
        # Verificar subdominios de whitelist
        for allowed_domain in self.whitelist:
            if domain == allowed_domain or domain.endswith('.' + allowed_domain):
                return True
        
        # YouTube esencial siempre permitido
        return domain in self.youtube_essential_domains

    def _is_youtube_related(self, domain: str) -> bool:
        """Verificar si el dominio está relacionado con YouTube"""
        return any(domain == yd or domain.endswith('.' + yd) for yd in self.youtube_essential_domains)

    def _is_youtube_ad(self, domain: str, url: str, headers: dict) -> bool:
        """Detección optimizada de anuncios de YouTube"""
        # NUNCA bloquear dominios esenciales de YouTube
        if domain in self.youtube_essential_domains:
            return False
            
        # Verificar patrones precompilados de ADS
        if (self.youtube_ad_patterns['ad_urls'].search(url) or
            self.youtube_ad_patterns['video_ads'].search(url) or
            self.youtube_ad_patterns['ad_params'].search(url)):
            return True

        # Verificar headers de anuncios
        user_agent = headers.get('User-Agent', '')
        referer = headers.get('Referer', '')
        
        if (self.youtube_ad_patterns['ad_headers'].search(user_agent) or
            self.youtube_ad_patterns['ad_headers'].search(referer)):
            return True

        return False

    async def filter_html_content(self, content: bytes, domain: str) -> bytes:
        """Filtrar contenido HTML de forma eficiente - ESPECIALMENTE YOUTUBE"""
        if not self._is_youtube_related(domain):
            return content

        try:
            # Ejecutar en thread pool para no bloquear el event loop
            loop = asyncio.get_event_loop()
            filtered_content = await loop.run_in_executor(
                self._thread_pool,
                self._filter_html_sync,
                content,
                domain
            )
            return filtered_content
            
        except Exception as e:
            logger.error(f"Error filtrando HTML para {domain}: {e}")
            return content

    def _filter_html_sync(self, content: bytes, domain: str) -> bytes:
        """Filtrar contenido HTML (ejecutado en thread pool) - ESPECIAL YOUTUBE"""
        try:
            html = content.decode('utf-8', errors='ignore')
            
            # Patrones de reemplazo específicos para YouTube ADS
            replacements = [
                # Scripts de anuncios de YouTube
                (r'<script[^>]*googlesyndication\.com[^>]*>.*?</script>', ''),
                (r'<script[^>]*doubleclick\.net[^>]*>.*?</script>', ''),
                (r'<script[^>]*googleadservices\.com[^>]*>.*?</script>', ''),
                (r'<script[^>]*adsystem\.com[^>]*>.*?</script>', ''),
                
                # Iframes de anuncios
                (r'<iframe[^>]*doubleclick\.net[^>]*>.*?</iframe>', ''),
                (r'<iframe[^>]*googleads\.g\.doubleclick\.net[^>]*>.*?</iframe>', ''),
                
                # Elementos DOM de anuncios de YouTube
                (r'<div[^>]*class="ytp-ad-[^"]*"[^>]*>.*?</div>', ''),
                (r'<div[^>]*id="player-ads"[^>]*>.*?</div>', ''),
                (r'<div[^>]*class="video-ads"[^>]*>.*?</div>', ''),
                (r'<div[^>]*class="ad-container"[^>]*>.*?</div>', ''),
                (r'<div[^>]*class="ad-overlay"[^>]*>.*?</div>', ''),
                
                # JSON de anuncios en YouTube
                (r'"adSlots":\s*\[[^\]]*\]', '"adSlots":[]'),
                (r'"playerAds":\s*\[[^\]]*\]', '"playerAds":[]'),
                (r'"adPlacements":\s*\[[^\]]*\]', '"adPlacements":[]'),
                (r'"adBreakUrl":\s*"[^"]*"', '"adBreakUrl":""'),
                
                # Overlays de anuncios
                (r'<div[^>]*id="ad-container"[^>]*>.*?</div>', ''),
                (r'<div[^>]*class="ytp-ad-message-container"[^>]*>.*?</div>', ''),
            ]
            
            for pattern, replacement in replacements:
                html = re.sub(pattern, replacement, html, flags=re.IGNORECASE | re.DOTALL)
            
            return html.encode('utf-8')
            
        except Exception as e:
            logger.error(f"Error en _filter_html_sync para {domain}: {e}")
            return content

    def add_to_whitelist(self, domain: str):
        """Añadir dominio a la lista blanca"""
        self.whitelist.add(domain)
        if domain in self.blocked_domains:
            self.blocked_domains.remove(domain)
        logger.info(f"✅ Dominio permitido: {domain}")

    def add_to_blacklist(self, domain: str):
        """Añadir dominio a la lista negra"""
        # No permitir bloquear dominios esenciales de YouTube
        if domain in self.youtube_essential_domains:
            logger.warning(f"⚠️  No se puede bloquear dominio esencial: {domain}")
            return
            
        self.blacklist.add(domain)
        logger.info(f"🚫 Dominio bloqueado: {domain}")

    def get_filter_stats(self) -> Dict:
        """Obtener estadísticas del filtro"""
        return {
            'whitelisted': len(self.whitelist),
            'blacklisted': len(self.blacklist),
            'blocked_domains': len(self.blocked_domains),
            'blocked_patterns': len(self.blocked_patterns),
            'total_requests': self.stats.total_requests,
            'blocked_requests': self.stats.blocked_requests,
            'youtube_ads_blocked': self.stats.youtube_ads_blocked,
            'whitelist_hits': self.stats.whitelist_hits,
            'cache_size': len(self._block_cache),
            'hit_rate': (
                (self.stats.blocked_requests / self.stats.total_requests * 100) 
                if self.stats.total_requests > 0 else 0
            )
        }

    async def cleanup(self):
        """Limpiar recursos"""
        if self._load_task and not self._load_task.done():
            self._load_task.cancel()
        
        self._thread_pool.shutdown(wait=False)
        self._block_cache.clear()
        
        logger.info("🧹 ContentFilter limpiado")
