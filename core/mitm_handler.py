# core/mitm_handler.py
import asyncio
import logging
import ssl
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urlparse
import aiohttp
from aiohttp import web
import OpenSSL
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

logger = logging.getLogger(__name__)

class CertificateAuthority:
    """Manejo de certificados CA para MITM"""
    
    def __init__(self, cert_dir: Path):
        self.cert_dir = cert_dir
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        
        self.ca_key_path = cert_dir / "ca.key"
        self.ca_cert_path = cert_dir / "ca.crt"
        self.generated_certs = {}
        
        self._ca_key = None
        self._ca_cert = None

    def generate_ca(self):
        """Generar Certificate Authority raíz"""
        if self.ca_key_path.exists() and self.ca_cert_path.exists():
            logger.info("✅ CA existente encontrada, cargando...")
            self._load_ca()
            return

        logger.info("🔐 Generando nueva Certificate Authority...")
        
        # Generar clave privada
        self._ca_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Crear subject para el CA
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Proxy Familiar CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Proxy Familiar Root CA"),
        ])
        
        # Crear certificado CA
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._ca_key.public_key()),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        
        self._ca_cert = cert
        
        # Guardar CA
        with open(self.ca_key_path, "wb") as f:
            f.write(self._ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        
        with open(self.ca_cert_path, "wb") as f:
            f.write(self._ca_cert.public_bytes(serialization.Encoding.PEM))
        
        logger.info("✅ Certificate Authority generada exitosamente")

    def _load_ca(self):
        """Cargar CA existente"""
        try:
            with open(self.ca_key_path, "rb") as f:
                self._ca_key = serialization.load_pem_private_key(f.read(), password=None)
            
            with open(self.ca_cert_path, "rb") as f:
                self._ca_cert = x509.load_pem_x509_certificate(f.read())
                
        except Exception as e:
            logger.error(f"❌ Error cargando CA: {e}")
            raise

    def generate_certificate(self, hostname: str) -> tuple[str, str]:
        """Generar certificado para un hostname específico"""
        if hostname in self.generated_certs:
            return self.generated_certs[hostname]
        
        # Generar clave privada para el certificado
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Crear subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Proxy Familiar"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        
        # Crear certificado
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(hostname),
                    x509.DNSName(f"*.{hostname}"),
                ]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        
        # Convertir a PEM
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        
        self.generated_certs[hostname] = (cert_pem, key_pem)
        logger.debug(f"🔐 Certificado generado para: {hostname}")
        
        return cert_pem, key_pem

class MITMHandler:
    """
    Man-in-the-Middle Handler para interceptar y modificar tráfico HTTPS.
    """
    
    def __init__(self, config: Dict[str, Any], content_filter, cache_manager):
        self.config = config
        self.content_filter = content_filter
        self.cache_manager = cache_manager
        self._running = False
        self._server = None
        self._ca = None
        self._session = None
        
        # Estadísticas
        self.stats = {
            'total_requests': 0,
            'https_intercepted': 0,
            'requests_blocked': 0,
            'requests_modified': 0,
            'errors': 0
        }

    async def start(self):
        """Iniciar el handler MITM"""
        if self._running:
            logger.warning("⚠️  MITMHandler ya está ejecutándose")
            return

        logger.info("🚀 Iniciando MITMHandler...")
        
        try:
            # Inicializar CA
            cert_dir = Path(self.config.get('cert_dir', 'config/certs'))
            self._ca = CertificateAuthority(cert_dir)
            self._ca.generate_ca()
            
            # Crear sesión HTTP compartida
            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=20)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                trust_env=True
            )
            
            # Configurar servidor MITM
            host = self.config.get('mitm_host', '0.0.0.0')
            port = self.config.get('mitm_port', 8082)
            
            app = web.Application()
            app.router.add_route('*', '/{path:.*}', self._handle_request)
            
            runner = web.AppRunner(app)
            await runner.setup()
            
            site = web.TCPSite(runner, host, port)
            await site.start()
            
            self._server = runner
            self._running = True
            
            logger.info(f"🌐 MITMHandler ejecutándose en {host}:{port}")
            logger.info("🔐 Interceptación HTTPS activa - Instala CA.crt para confiar en certificados")
            
        except Exception as e:
            logger.error(f"❌ Error iniciando MITMHandler: {e}")
            await self.stop()
            raise

    async def stop(self):
        """Detener el handler MITM"""
        if not self._running:
            return
            
        logger.info("🛑 Deteniendo MITMHandler...")
        self._running = False
        
        if self._server:
            await self._server.cleanup()
            self._server = None
            
        if self._session:
            await self._session.close()
            self._session = None
            
        logger.info("✅ MITMHandler detenido")

    async def _handle_request(self, request: web.Request) -> web.Response:
        """Manejar todas las requests HTTP/HTTPS"""
        self.stats['total_requests'] += 1
        
        try:
            # Obtener información de la request
            method = request.method
            url = str(request.url)
            headers = dict(request.headers)
            hostname = request.url.host
            
            logger.debug(f"🌐 {method} {url}")
            
            # Verificar si debemos bloquear esta request
            if await self.content_filter.should_block(hostname, url, headers):
                self.stats['requests_blocked'] += 1
                logger.info(f"🚫 Bloqueada: {url}")
                return web.Response(
                    status=403,
                    text="Bloqueado por Proxy Familiar",
                    headers={'Content-Type': 'text/plain'}
                )
            
            # Preparar headers para forward (remover algunos headers problemáticos)
            forward_headers = self._prepare_forward_headers(headers)
            
            # Leer body si existe
            body = await request.read() if request.can_read_body else None
            
            # Realizar la request real
            async with self._session.request(
                method=method,
                url=url,
                headers=forward_headers,
                data=body,
                allow_redirects=False,
                ssl=False  # Desactivar verificación SSL para MITM
            ) as response:
                
                # Procesar respuesta
                content = await response.read()
                content_type = response.headers.get('Content-Type', '')
                
                # Aplicar filtros de contenido si es HTML
                if (response.status == 200 and 
                    'text/html' in content_type and
                    await self.content_filter.should_block(hostname, url, headers) is False):
                    
                    filtered_content = await self.content_filter.filter_html_content(
                        content, hostname
                    )
                    
                    if filtered_content != content:
                        self.stats['requests_modified'] += 1
                        content = filtered_content
                        logger.debug(f"✂️  Contenido modificado para: {hostname}")
                
                # Crear respuesta
                response_headers = dict(response.headers)
                
                # Remover headers problemáticos
                for header in ['Content-Encoding', 'Transfer-Encoding', 'Content-Length']:
                    response_headers.pop(header, None)
                
                # Actualizar content-length
                response_headers['Content-Length'] = str(len(content))
                
                return web.Response(
                    status=response.status,
                    headers=response_headers,
                    body=content
                )
                
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"❌ Error procesando request {request.url}: {e}")
            return web.Response(
                status=502,
                text=f"Error de proxy: {str(e)}",
                headers={'Content-Type': 'text/plain'}
            )

    def _prepare_forward_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Preparar headers para forward, removiendo los problemáticos"""
        headers_to_remove = {
            'host', 'accept-encoding', 'content-length', 
            'transfer-encoding', 'connection'
        }
        
        forward_headers = {}
        for key, value in headers.items():
            if key.lower() not in headers_to_remove:
                forward_headers[key] = value
                
        return forward_headers

    def _create_ssl_context(self, hostname: str) -> ssl.SSLContext:
        """Crear contexto SSL con certificado generado para el hostname"""
        try:
            cert_pem, key_pem = self._ca.generate_certificate(hostname)
            
            # Crear contexto SSL
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Cargar certificado y clave
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as cert_file:
                cert_file.write(cert_pem)
                cert_path = cert_file.name
                
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as key_file:
                key_file.write(key_pem)
                key_path = key_file.name
                
            ssl_context.load_cert_chain(cert_path, key_path)
            
            # Limpiar archivos temporales
            Path(cert_path).unlink(missing_ok=True)
            Path(key_path).unlink(missing_ok=True)
            
            return ssl_context
            
        except Exception as e:
            logger.error(f"❌ Error creando contexto SSL para {hostname}: {e}")
            raise

    async def get_ca_certificate(self) -> str:
        """Obtener certificado CA en formato PEM"""
        if self._ca:
            with open(self._ca.ca_cert_path, 'r') as f:
                return f.read()
        return ""

    def get_stats(self) -> Dict[str, Any]:
        """Obtener estadísticas del MITMHandler"""
        return {
            **self.stats,
            'is_running': self._running,
            'generated_certs': len(self._ca.generated_certs) if self._ca else 0
        }

    async def clear_stats(self):
        """Limpiar estadísticas"""
        self.stats = {
            'total_requests': 0,
            'https_intercepted': 0,
            'requests_blocked': 0,
            'requests_modified': 0,
            'errors': 0
        }

# Función de utilidad para instalar la CA en el sistema
async def install_ca_certificate(ca_cert_pem: str) -> bool:
    """
    Instalar certificado CA en el sistema (requiere permisos de administrador)
    Esta es una implementación básica - en producción necesitarías platform-specific code
    """
    try:
        # Para Linux/macOS
        import platform
        system = platform.system()
        
        if system == "Darwin":  # macOS
            # Comando para instalar en Keychain de macOS
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.crt', delete=False) as f:
                f.write(ca_cert_pem)
                temp_path = f.name
            
            # Este comando requiere permisos de administrador
            import subprocess
            result = subprocess.run([
                'security', 'add-trusted-cert', '-d', '-r', 'trustRoot', 
                '-k', '/Library/Keychains/System.keychain', temp_path
            ], capture_output=True, text=True)
            
            Path(temp_path).unlink()
            return result.returncode == 0
            
        elif system == "Linux":
            # Para Linux, copiar a /usr/local/share/ca-certificates/
            cert_path = Path("/usr/local/share/ca-certificates/proxy-familiar-ca.crt")
            try:
                cert_path.write_text(ca_cert_pem)
                # Actualizar certificados del sistema
                import subprocess
                result = subprocess.run(['update-ca-certificates'], capture_output=True, text=True)
                return result.returncode == 0
            except PermissionError:
                logger.error("❌ Se requieren permisos de administrador para instalar CA")
                return False
                
        else:
            logger.warning(f"⚠️  Instalación automática de CA no soportada para {system}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Error instalando CA: {e}")
        return False
