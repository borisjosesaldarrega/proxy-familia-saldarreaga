import re
import aiohttp
import asyncio
from pathlib import Path
from typing import Set, List, Pattern, Dict
import logging

logger = logging.getLogger(__name__)

class ContentFilter:
    def __init__(self, config):
        self.config = config
        self.blocked_domains: Set[str] = set()
        self.blocked_patterns: List[Pattern] = []
        self.whitelist: Set[str] = set(config.get('whitelist', []))
        self.blacklist: Set[str] = set(config.get('blacklist', []))
        
        # Patrones específicos para YouTube
        self.youtube_ad_patterns = self._init_youtube_patterns()
        
        # Cargar listas de bloqueo al inicializar
        asyncio.create_task(self.load_block_lists())
    
    def _init_youtube_patterns(self) -> Dict[str, Pattern]:
        """Inicializar patrones específicos para anuncios de YouTube"""
        return {
            # URLs de anuncios
            'ad_urls': re.compile(r'(pagead|adlog|log_event|ptracking|get_midroll|videoplayback.*[&?](oad|ovad|adformat)=)', re.IGNORECASE),
            
            # Headers de anuncios
            'ad_headers': re.compile(r'(ads|advert|doubleclick|googleads)', re.IGNORECASE),
            
            # Scripts de anuncios en HTML
            'ad_scripts': re.compile(r'(adsystem|googleadservices|doubleclick\.net|googlesyndication)', re.IGNORECASE),
            
            # Elementos DOM de anuncios
            'ad_elements': re.compile(r'(ad-container|ad-unit|banner-ad|video-ads|ytp-ad-|ad-div|ad-overlay)', re.IGNORECASE),
            
            # Parámetros de URL específicos de ads
            'ad_params': re.compile(r'([?&](gclid|fbclid|utm_campaign|utm_source|utm_medium|utm_term)=)', re.IGNORECASE)
        }
    
    async def load_block_lists(self):
        """Cargar listas de bloqueo desde fuentes externas"""
        block_list_dir = Path("data/block_lists")
        block_list_dir.mkdir(parents=True, exist_ok=True)
        
        # Usar listas MÁS COMPATIBLES con mejor formato
        block_lists = [
            # Lista específica de YouTube con mejor formato
            ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/youtube.txt", "youtube_ads.txt"),
            # Lista general de anuncios (formato hosts)
            ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "steven_black.txt"),
            # Lista adicional de trackers
            ("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt", "tracking.txt"),
        ]
        
        for url, filename in block_lists:
            try:
                filepath = block_list_dir / filename
                if not filepath.exists():
                    await self.download_block_list(url, filepath)
                await self.parse_block_list(filepath)
                logger.info(f"✅ Lista cargada: {filename}")
            except Exception as e:
                logger.error(f"❌ Error cargando lista {url}: {e}")
    
    async def download_block_list(self, url: str, filepath: Path):
        """Descargar lista de bloqueo"""
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                content = await response.text()
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                logger.info(f"📥 Lista descargada: {filepath.name}")
    
    async def parse_block_list(self, filepath: Path):
        """Parsear archivo de lista de bloqueo con soporte para múltiples formatos"""
        count = 0
        filename = filepath.name
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                
            lines = content.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Saltar comentarios y líneas vacías
                if not line or line.startswith('!') or line.startswith('#'):
                    continue
                
                # FORMATO AdGuard: Líneas que contienen youtube.com
                if 'youtube.com' in line:
                    # Reglas de bloqueo de elementos (##selector)
                    if line.startswith('youtube.com##'):
                        selector = line[13:]  # Remover 'youtube.com##'
                        if selector:
                            pattern = self._css_selector_to_regex(selector)
                            if pattern:
                                self.blocked_patterns.append(pattern)
                                count += 1
                                continue
                    
                    # Reglas de excepción (#@#selector)
                    elif line.startswith('youtube.com#@#'):
                        continue
                    
                    # Reglas de scriptlets ($$scriptlet)
                    elif '$$' in line:
                        continue
                
                # FORMATO 1: Archivos hosts (127.0.0.1 dominio.com)
                if re.match(r'^\d+\.\d+\.\d+\.\d+\s+', line):
                    parts = line.split()
                    if len(parts) >= 2:
                        domain = parts[1]
                        if self._should_add_domain(domain):
                            self.blocked_domains.add(domain)
                            count += 1
                    continue
                
                # FORMATO 2: Reglas AdBlock (||dominio.com^)
                elif line.startswith('||') and line.endswith('^'):
                    domain = line[2:-1]
                    if self._should_add_domain(domain):
                        self.blocked_domains.add(domain)
                        pattern = re.compile(re.escape(domain), re.IGNORECASE)
                        self.blocked_patterns.append(pattern)
                        count += 1
                    continue
                
                # FORMATO 3: Reglas de elementos genéricas (##selector)
                elif line.startswith('##'):
                    selector = line[2:]
                    if selector:
                        pattern = self._css_selector_to_regex(selector)
                        if pattern:
                            self.blocked_patterns.append(pattern)
                            count += 1
                    continue
                
                # FORMATO 4: Reglas de excepción (@@||dominio.com^)
                elif line.startswith('@@||') and line.endswith('^'):
                    domain = line[4:-1]
                    self.whitelist.add(domain)
                    count += 1
                    continue
                
                # FORMATO 5: Dominios simples
                elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
                    if self._should_add_domain(line):
                        self.blocked_domains.add(line)
                        count += 1
                    continue
                
                # FORMATO 6: Líneas que contienen palabras clave de anuncios
                elif any(keyword in line.lower() for keyword in ['ad', 'ads', 'banner', 'track', 'analytics', 'doubleclick']):
                    # Intentar extraer dominio
                    domain_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', line)
                    if domain_match:
                        domain = domain_match.group(1)
                        if self._should_add_domain(domain):
                            self.blocked_domains.add(domain)
                            count += 1
            
            logger.info(f"📋 {count} reglas cargadas de {filename}")
            
        except Exception as e:
            logger.error(f"❌ Error parseando {filename}: {e}")

    def _css_selector_to_regex(self, selector: str) -> Pattern:
        """Convertir selector CSS a patrón regex para búsqueda en HTML"""
        try:
            # Limpiar selector
            selector = selector.strip()
            if not selector:
                return None
            
            # Selectores específicos de YouTube ads
            youtube_selectors = {
                # Anuncios overlay de YouTube
                '.ytp-ad-module': r'<[^>]*class=[^>]*ytp-ad-module[^>]*>.*?</[^>]*>',
                '.ytp-ad-overlay-container': r'<[^>]*class=[^>]*ytp-ad-overlay-container[^>]*>.*?</[^>]*>',
                '.ytp-ad-player-overlay': r'<[^>]*class=[^>]*ytp-ad-player-overlay[^>]*>.*?</[^>]*>',
                '.ytp-ad-message': r'<[^>]*class=[^>]*ytp-ad-message[^>]*>.*?</[^>]*>',
                # Botones de skip
                '.ytp-ad-skip-button': r'<[^>]*class=[^>]*ytp-ad-skip-button[^>]*>.*?</[^>]*>',
                '.ytp-ad-skip-button-modern': r'<[^>]*class=[^>]*ytp-ad-skip-button-modern[^>]*>.*?</[^>]*>',
                # Anuncios de video
                '.video-ads': r'<[^>]*class=[^>]*video-ads[^>]*>.*?</[^>]*>',
                # Contenedores de anuncios
                '#player-ads': r'<[^>]*id=[^>]*player-ads[^>]*>.*?</[^>]*>',
                '.ad-container': r'<[^>]*class=[^>]*ad-container[^>]*>.*?</[^>]*>',
                '.ad-div': r'<[^>]*class=[^>]*ad-div[^>]*>.*?</[^>]*>',
                # Cualquier elemento con "ad" en la clase
                '[class*="ad"]': r'<[^>]*class=[^>]*ad[^>]*>.*?</[^>]*>',
                '.ad': r'<[^>]*class=[^>]*\bad\b[^>]*>.*?</[^>]*>',
                '.ads': r'<[^>]*class=[^>]*\bads\b[^>]*>.*?</[^>]*>',
            }
            
            # Buscar selector conocido
            for css_pattern, regex_pattern in youtube_selectors.items():
                if css_pattern in selector:
                    return re.compile(regex_pattern, re.IGNORECASE | re.DOTALL)
            
            # Patrón genérico para selectores de clase
            if selector.startswith('.'):
                class_name = selector[1:]
                # Manejar wildcards en nombres de clase
                if '*' in class_name:
                    class_name = class_name.replace('*', '.*')
                return re.compile(
                    f'<[^>]*class=[^>]*{re.escape(class_name)}[^>]*>.*?</[^>]*>',
                    re.IGNORECASE | re.DOTALL
                )
            
            # Patrón genérico para selectores de ID
            elif selector.startswith('#'):
                id_name = selector[1:]
                return re.compile(
                    f'<[^>]*id=[^>]*{re.escape(id_name)}[^>]*>.*?</[^>]*>',
                    re.IGNORECASE | re.DOTALL
                )
            
            # Selector por atributo
            elif selector.startswith('[') and selector.endswith(']'):
                attr_selector = selector[1:-1]
                return re.compile(
                    f'<[^>]*{re.escape(attr_selector)}[^>]*>.*?</[^>]*>',
                    re.IGNORECASE | re.DOTALL
                )
            
            logger.debug(f"Selector no procesado: {selector}")
            return None
            
        except Exception as e:
            logger.error(f"Error convirtiendo selector CSS {selector}: {e}")
            return None
        
    def _should_add_domain(self, domain: str) -> bool:
        """Verificar si se debe añadir un dominio a la lista de bloqueo"""
        if domain in self.whitelist:
            return False
        
        # No bloquear dominios esenciales de YouTube
        essential_domains = [
            'youtube.com', 'www.youtube.com', 'youtu.be', 
            'ggpht.com', 'ytimg.com', 'google.com'
        ]
        
        # Verificar si es subdominio de YouTube esencial
        for essential in essential_domains:
            if domain == essential or domain.endswith('.' + essential):
                return False
        
        return True
    
    async def should_block(self, domain: str, url: str, headers: dict) -> bool:
        """Determinar si bloquear una petición"""
        if not self.config.get('blocking_enabled', True):
            return False
        
        # Verificar lista blanca
        if self._is_whitelisted(domain, url):
            return False
        
        # Verificar lista negra manual
        if domain in self.blacklist:
            logger.info(f"🚫 Bloqueado por blacklist: {domain}")
            return True
        
        # Verificar dominios bloqueados
        if domain in self.blocked_domains:
            logger.info(f"🚫 Bloqueado por lista: {domain}")
            return True
        
        # Verificar patrones de URL
        for pattern in self.blocked_patterns:
            if pattern.search(url):
                logger.info(f"🚫 Bloqueado por patrón: {domain} - {url[:100]}...")
                return True
        
        # Filtrado específico para YouTube
        if self.config.get('youtube_blocking', True) and self._is_youtube_related(domain):
            if self._is_youtube_ad(domain, url, headers):
                logger.info(f"🎯 Bloqueado anuncio YouTube: {domain} - {url[:100]}...")
                return True
        
        return False
    
    def _is_whitelisted(self, domain: str, url: str) -> bool:
        """Verificar si está en la lista blanca"""
        if domain in self.whitelist:
            return True
        
        # YouTube principal siempre permitido
        if domain in ['youtube.com', 'www.youtube.com']:
            return True
        
        # Verificar subdominios de whitelist
        for allowed_domain in self.whitelist:
            if domain.endswith('.' + allowed_domain) or domain == allowed_domain:
                return True
        
        return False
    
    def _is_youtube_related(self, domain: str) -> bool:
        """Verificar si el dominio está relacionado con YouTube"""
        youtube_domains = [
            'youtube.com', 'youtu.be', 'googlevideo.com', 
            'ytimg.com', 'ggpht.com', 'googleapis.com',
            'google.com', 'gstatic.com'
        ]
        return any(domain == yd or domain.endswith('.' + yd) for yd in youtube_domains)
    
    def _is_youtube_ad(self, domain: str, url: str, headers: dict) -> bool:
        """Detectar anuncios de YouTube de forma más agresiva"""
        
        # 1. Verificar URLs de anuncios
        if self.youtube_ad_patterns['ad_urls'].search(url):
            return True
        
        # 2. Verificar headers de anuncios
        user_agent = headers.get('User-Agent', '')
        referer = headers.get('Referer', '')
        
        if (self.youtube_ad_patterns['ad_headers'].search(user_agent) or
            self.youtube_ad_patterns['ad_headers'].search(referer)):
            return True
        
        # 3. Verificar parámetros de URL específicos para ads
        if self.youtube_ad_patterns['ad_params'].search(url):
            return True
        
        # 4. Patrones específicos de video ads
        ad_indicators = [
            # Anuncios de video
            r'/videoplayback.*[&?]ctier=',
            r'/videoplayback.*[&?]oad=',
            r'/videoplayback.*[&?]ovad=',
            r'/videoplayback.*[&?]of=',
            r'/videoplayback.*[&?]adformat=',
            # Tracking
            r'/ptracking\?',
            r'/api/stats/',
            r'/log_event\?',
            # Anuncios mid-roll
            r'/get_midroll_',
            # Google ads
            r'google\.com/pagead',
            r'googleadservices\.com',
            r'doubleclick\.net',
        ]
        
        return any(re.search(pattern, url, re.IGNORECASE) for pattern in ad_indicators)
    
    async def filter_html_content(self, content: bytes, domain: str) -> bytes:
        """Filtrar contenido HTML específicamente para YouTube"""
        try:
            html = content.decode('utf-8', errors='ignore')
            
            # Solo filtrar si es YouTube
            if not self._is_youtube_related(domain):
                return content
            
            # Eliminar scripts de anuncios
            html = re.sub(
                r'<script[^>]*(adsystem|googleadservices|doubleclick|googlesyndication)[^>]*>.*?</script>',
                '',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            
            # Eliminar iframes de anuncios
            html = re.sub(
                r'<iframe[^>]*(ad|banner|ads)[^>]*>.*?</iframe>',
                '',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            
            # Eliminar elementos DOM de anuncios de YouTube
            html = re.sub(
                r'<div[^>]*(ad-container|ad-unit|video-ads|ytp-ad-)[^>]*>.*?</div>',
                '',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            
            # Eliminar overlays de anuncios
            html = re.sub(
                r'<div[^>]*ad-overlay[^>]*>.*?</div>',
                '',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            
            # Bloquear player ads (muy importante)
            html = re.sub(
                r'"playerAds":\s*\[[^\]]*\],?',
                '"playerAds":[],',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            
            # Bloquear ad placements
            html = re.sub(
                r'"adPlacements":\s*\[[^\]]*\],?',
                '"adPlacements":[],',
                html,
                flags=re.IGNORECASE | re.DOTALL
            )
            
            logger.info(f"🎯 HTML filtrado para: {domain}")
            return html.encode('utf-8')
            
        except Exception as e:
            logger.error(f"Error filtering HTML for {domain}: {e}")
            return content
    
    def add_to_whitelist(self, domain: str):
        """Añadir dominio a la lista blanca"""
        self.whitelist.add(domain)
        if domain in self.blocked_domains:
            self.blocked_domains.remove(domain)
        logger.info(f"✅ Dominio permitido: {domain}")
    
    def add_to_blacklist(self, domain: str):
        """Añadir dominio a la lista negra"""
        self.blacklist.add(domain)
        logger.info(f"🚫 Dominio bloqueado: {domain}")
    
    def get_filter_stats(self) -> Dict:
        """Obtener estadísticas del filtro"""
        return {
            'whitelisted': len(self.whitelist),
            'blacklisted': len(self.blacklist),
            'blocked_domains': len(self.blocked_domains),
            'blocked_patterns': len(self.blocked_patterns)
        }