import asyncio
import aiohttp
from aiohttp import web
import logging
from urllib.parse import urlparse
from typing import Optional, Dict, Any
import ssl
import time

from .content_filter import ContentFilter
from .cache_manager import CacheManager
from data.database import log_request, update_statistics

logger = logging.getLogger(__name__)

class AdvancedProxyServer:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Inicializar componentes esenciales - SIN MITMHandler
        self.content_filter = ContentFilter(config)
        self.cache_manager = CacheManager(config) if config.get('cache_enabled', True) else None
        
        # ELIMINADO: self.mitm_handler = MITMHandler(config)
        
        self.session: Optional[aiohttp.ClientSession] = None
        self.server: Optional[asyncio.Server] = None
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'cached_responses': 0,
            'domains_visited': {},
            'youtube_ads_blocked': 0
        }
        
        # Inicializar el content filter
        asyncio.create_task(self._initialize_components())
    
    async def _initialize_components(self):
        """Inicializar componentes asíncronos"""
        try:
            await self.content_filter.initialize()
            logger.info("✅ ContentFilter inicializado correctamente")
        except Exception as e:
            logger.error(f"❌ Error inicializando ContentFilter: {e}")
    
    async def start(self):
        """Iniciar el servidor proxy con soporte para HTTP/HTTPS"""
        # Configurar session con timeout
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        
        # Crear servidor raw para manejar CONNECT (HTTPS)
        self.server = await asyncio.start_server(
            self.handle_raw_client,
            self.config['proxy_host'], 
            self.config['proxy_port']
        )
        
        logger.info(f"🚀 Proxy server started on {self.config['proxy_host']}:{self.config['proxy_port']}")
        logger.info("✅ HTTP and HTTPS forwarding enabled")
        logger.info(f"✅ Blocking enabled: {self.config.get('blocking_enabled', True)}")
        logger.info(f"✅ YouTube blocking: {self.config.get('youtube_blocking', True)}")
        
        # Mantener el servidor corriendo
        async with self.server:
            await self.server.serve_forever()
    
    async def stop(self):
        """Detener el servidor proxy"""
        if self.session:
            await self.session.close()
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        await self.content_filter.cleanup()
        logger.info("🛑 Proxy server stopped")
    
    async def handle_raw_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Manejar conexiones raw para soportar HTTP y HTTPS"""
        client_ip = writer.get_extra_info('peername')[0] if writer.get_extra_info('peername') else 'unknown'
        
        try:
            # Leer la primera línea de la solicitud
            data = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), timeout=10.0)
            request_lines = data.decode('utf-8', errors='ignore').split('\r\n')
            first_line = request_lines[0]
            
            if not first_line:
                return
                
            parts = first_line.split()
            if len(parts) < 2:
                return
                
            method, target = parts[0], parts[1]
            
            logger.debug(f"📨 [{client_ip}] {method} {target}")
            
            # Manejar método CONNECT (HTTPS tunneling)
            if method.upper() == 'CONNECT':
                await self.handle_https_connect(reader, writer, target, client_ip)
            else:
                # Manejar HTTP normal
                await self.handle_http_request(reader, writer, data, method, target, client_ip)
                
        except asyncio.TimeoutError:
            logger.warning(f"⏰ Timeout reading request from {client_ip}")
        except Exception as e:
            logger.error(f"❌ Error handling client {client_ip}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def handle_https_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target: str, client_ip: str):
        """Manejar tunneling HTTPS (CONNECT)"""
        try:
            host, port = target.split(':') if ':' in target else (target, '443')
            port = int(port)
            
            # Extraer headers para análisis
            initial_data = await reader.read(4096)  # Leer datos iniciales después de CONNECT
            headers = self._extract_headers_from_data(initial_data)
            
            # Verificar bloqueo antes de conectar
            if await self.content_filter.should_block(host, f"https://{target}", headers):
                self.stats['blocked_requests'] += 1
                if 'youtube' in host.lower() or 'googlevideo' in host.lower():
                    self.stats['youtube_ads_blocked'] += 1
                await log_request(host, f"https://{target}", 'BLOCKED')
                await update_statistics(host, blocked=True)
                
                logger.info(f"🚫 BLOCKED HTTPS: {host}")
                writer.write(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                await writer.drain()
                return
            
            logger.debug(f"🔗 HTTPS CONNECT to {host}:{port}")
            
            # Conectar al servidor destino
            target_reader, target_writer = await asyncio.open_connection(host, port, ssl=False)
            
            # Enviar respuesta de conexión establecida
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()
            
            # Reenviar datos iniciales si los hay
            if initial_data:
                target_writer.write(initial_data)
                await target_writer.drain()
            
            # Crear tunnel bidireccional
            await asyncio.gather(
                self.forward_data(reader, target_writer, f"client->{host}"),
                self.forward_data(target_reader, writer, f"{host}->client"),
                return_exceptions=True
            )
            
        except Exception as e:
            logger.error(f"❌ HTTPS CONNECT error for {target}: {e}")
            try:
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await writer.drain()
            except:
                pass
    
    async def handle_http_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, 
                                initial_data: bytes, method: str, target: str, client_ip: str):
        """Manejar peticiones HTTP normales"""
        try:
            # Reconstruir la URL completa
            if target.startswith('http'):
                url = target
            else:
                # Encontrar el header Host
                headers_data = initial_data.decode('utf-8', errors='ignore')
                host_header = None
                for line in headers_data.split('\r\n'):
                    if line.lower().startswith('host:'):
                        host_header = line.split(':', 1)[1].strip()
                        break
                
                if host_header:
                    url = f"http://{host_header}{target}"
                else:
                    url = f"http://{target}"
            
            domain = urlparse(url).hostname or 'unknown'
            
            # Extraer headers para el filtro
            headers = self._extract_headers_from_data(initial_data)
            
            # Verificar bloqueo
            if await self.content_filter.should_block(domain, url, headers):
                self.stats['blocked_requests'] += 1
                if 'youtube' in domain.lower() or 'googlevideo' in domain.lower():
                    self.stats['youtube_ads_blocked'] += 1
                await log_request(domain, url, 'BLOCKED')
                await update_statistics(domain, blocked=True)
                
                logger.info(f"🚫 BLOCKED HTTP: {domain} - {url}")
                blocked_response = self._create_blocked_response(domain)
                writer.write(blocked_response)
                await writer.drain()
                return
            
            # Procesar la petición HTTP
            response = await self.process_http_request(method, url, initial_data, domain, headers, client_ip)
            writer.write(response)
            await writer.drain()
            
        except Exception as e:
            logger.error(f"❌ HTTP request error from {client_ip}: {e}")
            try:
                error_response = b'HTTP/1.1 500 Internal Server Error\r\n\r\n'
                writer.write(error_response)
                await writer.drain()
            except:
                pass
    
    async def process_http_request(self, method: str, url: str, initial_data: bytes, domain: str, headers: dict, client_ip: str) -> bytes:
        """Procesar petición HTTP y generar respuesta"""
        self.stats['total_requests'] += 1
        
        logger.debug(f"🌐 Processing {method} {url}")

        # Verificar caché para GET
        if method.upper() == 'GET' and self.cache_manager:
            cached_response = await self.cache_manager.get(url)
            if cached_response:
                self.stats['cached_responses'] += 1
                await log_request(domain, url, 'CACHED')
                logger.debug(f"💾 CACHE HIT: {domain}")
                return self._build_http_response(cached_response)
        
        try:
            # Preparar headers para la petición externa
            request_headers = self._clean_headers(initial_data)
            
            # Realizar la petición real
            async with self.session.request(
                method.upper(),
                url,
                headers=request_headers,
                data=initial_data.split(b'\r\n\r\n')[1] if b'\r\n\r\n' in initial_data else None,
                ssl=False,
                allow_redirects=True
            ) as response:
                
                content = await response.read()
                content_type = response.headers.get('Content-Type', '')
                
                # Filtrar contenido HTML
                if 'text/html' in content_type and self.config.get('blocking_enabled', True):
                    filtered_content = await self.content_filter.filter_html_content(content, domain)
                    if filtered_content != content:
                        logger.debug(f"🎯 Filtered HTML content for {domain}")
                    content = filtered_content
                
                # Cachear si es apropiado
                if (method.upper() == 'GET' and self.cache_manager and 
                    response.status == 200 and self._is_cacheable(content_type, domain)):
                    await self.cache_manager.set(url, {
                        'status': response.status,
                        'headers': dict(response.headers),
                        'body': content
                    })
                
                # Log y estadísticas
                status = 'ALLOWED'
                await log_request(domain, url, status)
                await update_statistics(domain, blocked=False)
                self._update_domain_stats(domain)
                
                logger.debug(f"✅ {status}: {domain} - Status: {response.status}")
                
                return self._build_http_response({
                    'status': response.status,
                    'headers': dict(response.headers),
                    'body': content
                })
                
        except Exception as e:
            logger.error(f"❌ Error fetching {url}: {e}")
            return b'HTTP/1.1 502 Bad Gateway\r\n\r\n'
    
    async def forward_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, label: str):
        """Reenviar datos entre cliente y servidor"""
        try:
            while True:
                data = await reader.read(8192)  # Buffer más grande para mejor rendimiento
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception as e:
            logger.debug(f"🔌 Forwarding stopped for {label}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    def _extract_headers_from_data(self, data: bytes) -> dict:
        """Extraer headers del data de la petición"""
        headers = {}
        try:
            request_str = data.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')[1:]  # Saltar primera línea
            
            for line in lines:
                if not line.strip():
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
        except Exception as e:
            logger.debug(f"Error extracting headers: {e}")
        
        return headers
    
    def _clean_headers(self, request_data: bytes) -> Dict[str, str]:
        """Limpiar headers para la petición externa"""
        headers = {}
        request_str = request_data.decode('utf-8', errors='ignore')
        lines = request_str.split('\r\n')[1:]  # Saltar primera línea
        
        for line in lines:
            if not line.strip():
                break
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                # Mantener headers útiles, remover problemáticos
                if key not in ['proxy-connection', 'accept-encoding']:
                    headers[key] = value.strip()
        
        # Asegurar header Host
        if 'host' not in headers:
            # Extraer host de la primera línea si es posible
            first_line = request_str.split('\r\n')[0]
            if 'http' in first_line:
                try:
                    from urllib.parse import urlparse
                    url = first_line.split()[1]
                    host = urlparse(url).hostname
                    if host:
                        headers['host'] = host
                except:
                    pass
        
        return headers
    
    def _build_http_response(self, response_data: Dict) -> bytes:
        """Construir respuesta HTTP en bytes"""
        status_line = f"HTTP/1.1 {response_data['status']}\r\n"
        headers = ""
        
        for key, value in response_data['headers'].items():
            if key.lower() not in ['transfer-encoding', 'content-encoding', 'content-length']:
                headers += f"{key}: {value}\r\n"
        
        headers += f"Content-Length: {len(response_data['body'])}\r\n"
        headers += "Connection: close\r\n"
        
        return f"{status_line}{headers}\r\n".encode() + response_data['body']
    
    def _create_blocked_response(self, domain: str) -> bytes:
        """Crear respuesta de bloqueo"""
        html_content = f"""
        <html>
        <head>
            <title>Acceso Bloqueado - Proxy Familiar</title>
            <style>
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    text-align: center; 
                    padding: 50px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    min-height: 100vh;
                    display: flex;
                    flex-direction: column;
                    justify-content: center;
                    align-items: center;
                }}
                .container {{
                    background: rgba(255, 255, 255, 0.1);
                    padding: 40px;
                    border-radius: 15px;
                    backdrop-filter: blur(10px);
                    max-width: 500px;
                }}
                h1 {{ color: #ff6b6b; margin-bottom: 20px; }}
                p {{ font-size: 16px; line-height: 1.6; margin: 10px 0; }}
                .domain {{ 
                    background: rgba(255, 255, 255, 0.2); 
                    padding: 10px; 
                    border-radius: 5px; 
                    font-family: monospace;
                    margin: 15px 0;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔒 Acceso Bloqueado</h1>
                <p>El dominio ha sido bloqueado por el proxy familiar.</p>
                <div class="domain">{domain}</div>
                <p>Si crees que esto es un error, contacta al administrador.</p>
                <p><small>Sistema de Protección Familiar</small></p>
            </div>
        </body>
        </html>
        """
        
        response = f"""HTTP/1.1 403 Forbidden
Content-Type: text/html; charset=utf-8
Content-Length: {len(html_content)}
Connection: close

{html_content}"""
        
        return response.encode()
    
    def _is_cacheable(self, content_type: str, domain: str) -> bool:
        """Determinar si el contenido es cacheable"""
        # No cachear contenido de YouTube para evitar problemas
        if 'youtube' in domain.lower() or 'googlevideo' in domain.lower():
            return False
            
        cacheable_types = [
            'text/css', 'application/javascript', 'image/',
            'font/', 'text/plain'
        ]
        return any(ct in content_type for ct in cacheable_types)
    
    def _update_domain_stats(self, domain: str):
        """Actualizar estadísticas de dominios visitados"""
        if domain in self.stats['domains_visited']:
            self.stats['domains_visited'][domain] += 1
        else:
            self.stats['domains_visited'][domain] = 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtener estadísticas actuales"""
        stats = self.stats.copy()
        stats['unique_domains'] = len(stats['domains_visited'])
        
        # Añadir estadísticas del content filter
        try:
            filter_stats = self.content_filter.get_filter_stats()
            stats.update(filter_stats)
        except Exception as e:
            logger.debug(f"Could not get filter stats: {e}")
        
        # Calcular hit rate
        if stats['total_requests'] > 0:
            stats['hit_rate'] = round((stats['blocked_requests'] / stats['total_requests']) * 100, 2)
        else:
            stats['hit_rate'] = 0
            
        return stats
    
    def reset_stats(self):
        """Reiniciar estadísticas"""
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'cached_responses': 0,
            'domains_visited': {},
            'youtube_ads_blocked': 0
        }
