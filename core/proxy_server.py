import asyncio
import aiohttp
from aiohttp import web
import logging
from urllib.parse import urlparse
from typing import Optional, Dict, Any
import ssl

from .mitm_handler import MITMHandler
from .content_filter import ContentFilter
from .cache_manager import CacheManager
from data.database import log_request, update_statistics

logger = logging.getLogger(__name__)

class AdvancedProxyServer:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.mitm_handler = MITMHandler(config)
        self.content_filter = ContentFilter(config)
        self.cache_manager = CacheManager(config) if config['cache_enabled'] else None
        self.session: Optional[aiohttp.ClientSession] = None
        self.server: Optional[asyncio.Server] = None
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'cached_responses': 0,
            'domains_visited': {}
        }
    
    async def start(self):
        """Iniciar el servidor proxy con soporte para HTTP/HTTPS"""
        self.session = aiohttp.ClientSession()
        
        # Crear servidor raw para manejar CONNECT (HTTPS)
        self.server = await asyncio.start_server(
            self.handle_raw_client,
            self.config['proxy_host'], 
            self.config['proxy_port']
        )
        
        logger.info(f"🚀 Proxy server started on {self.config['proxy_host']}:{self.config['proxy_port']}")
        logger.info("✅ HTTP and HTTPS forwarding enabled")
        
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
        logger.info("Proxy server stopped")
    
    async def handle_raw_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Manejar conexiones raw para soportar HTTP y HTTPS"""
        try:
            # Leer la primera línea de la solicitud
            data = await reader.readuntil(b'\r\n\r\n')
            request_lines = data.decode('utf-8', errors='ignore').split('\r\n')
            first_line = request_lines[0]
            
            if not first_line:
                return
                
            parts = first_line.split()
            if len(parts) < 2:
                return
                
            method, target = parts[0], parts[1]
            
            # Manejar método CONNECT (HTTPS tunneling)
            if method.upper() == 'CONNECT':
                await self.handle_https_connect(reader, writer, target)
            else:
                # Manejar HTTP normal
                await self.handle_http_request(reader, writer, data, method, target)
                
        except Exception as e:
            logger.error(f"Error handling client: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def handle_https_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target: str):
        """Manejar tunneling HTTPS (CONNECT)"""
        try:
            host, port = target.split(':') if ':' in target else (target, '443')
            port = int(port)
            
            # Verificar bloqueo antes de conectar
            if await self.content_filter.should_block(host, f"https://{target}", {}):
                self.stats['blocked_requests'] += 1
                await log_request(host, f"https://{target}", 'BLOCKED')
                writer.write(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                await writer.drain()
                return
            
            # Conectar al servidor destino
            target_reader, target_writer = await asyncio.open_connection(host, port)
            
            # Enviar respuesta de conexión establecida
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()
            
            # Crear tunnel bidireccional
            await asyncio.gather(
                self.forward_data(reader, target_writer, f"client->{host}"),
                self.forward_data(target_reader, writer, f"{host}->client")
            )
            
        except Exception as e:
            logger.error(f"HTTPS CONNECT error for {target}: {e}")
            try:
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await writer.drain()
            except:
                pass
    
    async def handle_http_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, 
                                initial_data: bytes, method: str, target: str):
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
            
            domain = urlparse(url).hostname
            
            # Verificar bloqueo
            if await self.content_filter.should_block(domain, url, {}):
                self.stats['blocked_requests'] += 1
                await log_request(domain, url, 'BLOCKED')
                await update_statistics(domain, blocked=True)
                
                blocked_response = self._create_blocked_response(domain)
                writer.write(blocked_response)
                await writer.drain()
                return
            
            # Procesar la petición HTTP
            response = await self.process_http_request(method, url, initial_data, domain)
            writer.write(response)
            await writer.drain()
            
        except Exception as e:
            logger.error(f"HTTP request error: {e}")
            try:
                error_response = b'HTTP/1.1 500 Internal Server Error\r\n\r\n'
                writer.write(error_response)
                await writer.drain()
            except:
                pass
    
    async def process_http_request(self, method: str, url: str, initial_data: bytes, domain: str) -> bytes:
        """Procesar petición HTTP y generar respuesta"""
        self.stats['total_requests'] += 1
        
        # Verificar caché para GET
        if method.upper() == 'GET' and self.cache_manager:
            cached_response = await self.cache_manager.get(url)
            if cached_response:
                self.stats['cached_responses'] += 1
                await log_request(domain, url, 'CACHED')
                return self._build_http_response(cached_response)
        
        try:
            # Realizar la petición real
            async with self.session.request(
                method.upper(),
                url,
                headers=self._clean_headers(initial_data),
                data=initial_data.split(b'\r\n\r\n')[1] if b'\r\n\r\n' in initial_data else None,
                ssl=False
            ) as response:
                
                content = await response.read()
                content_type = response.headers.get('Content-Type', '')
                
                # Filtrar contenido HTML
                if 'text/html' in content_type and self.config['blocking_enabled']:
                    content = await self.content_filter.filter_html_content(content, domain)
                
                # Cachear si es apropiado
                if (method.upper() == 'GET' and self.cache_manager and 
                    response.status == 200 and self._is_cacheable(content_type)):
                    await self.cache_manager.set(url, {
                        'status': response.status,
                        'headers': dict(response.headers),
                        'body': content
                    })
                
                # Log y estadísticas
                await log_request(domain, url, 'ALLOWED')
                await update_statistics(domain, blocked=False)
                self._update_domain_stats(domain)
                
                return self._build_http_response({
                    'status': response.status,
                    'headers': dict(response.headers),
                    'body': content
                })
                
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return b'HTTP/1.1 502 Bad Gateway\r\n\r\n'
    
    async def forward_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, label: str):
        """Reenviar datos entre cliente y servidor"""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception as e:
            logger.debug(f"Forwarding stopped for {label}: {e}")
        finally:
            try:
                writer.close()
            except:
                pass
    
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
                key = key.strip()
                # Remover headers problemáticos
                if key.lower() not in ['host', 'proxy-connection', 'accept-encoding']:
                    headers[key] = value.strip()
        
        return headers
    
    def _build_http_response(self, response_data: Dict) -> bytes:
        """Construir respuesta HTTP en bytes"""
        status_line = f"HTTP/1.1 {response_data['status']}\r\n"
        headers = ""
        
        for key, value in response_data['headers'].items():
            if key.lower() not in ['transfer-encoding', 'content-encoding']:
                headers += f"{key}: {value}\r\n"
        
        headers += f"Content-Length: {len(response_data['body'])}\r\n"
        headers += "Connection: close\r\n"
        
        return f"{status_line}{headers}\r\n".encode() + response_data['body']
    
    def _create_blocked_response(self, domain: str) -> bytes:
        """Crear respuesta de bloqueo"""
        html_content = f"""
        <html>
        <head><title>Acceso Bloqueado</title></head>
        <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
            <h1 style="color: #d32f2f;">🔒 Acceso Bloqueado</h1>
            <p>El dominio <strong>{domain}</strong> ha sido bloqueado por el proxy doméstico.</p>
            <p>Si crees que esto es un error, contacta al administrador.</p>
        </body>
        </html>
        """
        
        response = f"""HTTP/1.1 403 Forbidden
Content-Type: text/html
Content-Length: {len(html_content)}
Connection: close

{html_content}"""
        
        return response.encode()
    
    def _is_cacheable(self, content_type: str) -> bool:
        """Determinar si el contenido es cacheable"""
        cacheable_types = [
            'text/css', 'application/javascript', 'image/',
            'video/', 'audio/', 'font/', 'text/html'
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
        return stats
    
    def reset_stats(self):
        """Reiniciar estadísticas"""
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'cached_responses': 0,
            'domains_visited': {}
        }