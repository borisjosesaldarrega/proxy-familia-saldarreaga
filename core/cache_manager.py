# core/cache_manager.py
import asyncio
import logging
from typing import Any, Optional, Dict, List, Callable
from time import time
import hashlib
import pickle

logger = logging.getLogger(__name__)

class CacheItem:
    __slots__ = ("value", "expires_at", "created_at", "access_count")
    
    def __init__(self, value: Any, expires_at: Optional[float]):
        self.value = value
        self.expires_at = expires_at
        self.created_at = time()
        self.access_count = 0

class CacheManager:
    """
    CacheManager asíncrono mejorado para proxy con optimizaciones.
    - Soporte TTL con limpieza eficiente
    - Estadísticas de uso
    - Compresión opcional de datos
    - Límite de memoria automático
    - Búsqueda por patrones
    """

    def __init__(self, 
                 cleanup_interval: float = 30.0,
                 max_size: int = 1000,
                 enable_compression: bool = False):
        """
        :param cleanup_interval: intervalo de limpieza en segundos
        :param max_size: número máximo de items en caché
        :param enable_compression: comprimir datos grandes
        """
        self._store: Dict[str, CacheItem] = {}
        self._lock = asyncio.Lock()
        self._cleanup_interval = cleanup_interval
        self._max_size = max_size
        self._enable_compression = enable_compression
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Estadísticas
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    async def init(self) -> None:
        """Inicializa recursos y lanza tarea de limpieza."""
        if not self._running:
            self._running = True
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info("✅ CacheManager iniciado (cleanup: %ss, max_size: %d)", 
                       self._cleanup_interval, self._max_size)

    async def close(self) -> None:
        """Detiene la tarea de limpieza y libera recursos."""
        if self._running:
            self._running = False
            if self._cleanup_task:
                self._cleanup_task.cancel()
                try:
                    await self._cleanup_task
                except asyncio.CancelledError:
                    pass
            logger.info("🛑 CacheManager detenido - Hits: %d, Misses: %d", self._hits, self._misses)

    async def _cleanup_loop(self) -> None:
        """Loop que periódicamente borra keys expiradas y gestiona memoria."""
        try:
            while self._running:
                await asyncio.sleep(self._cleanup_interval)
                await self._purge_expired()
                await self._enforce_memory_limits()
        except asyncio.CancelledError:
            await self._purge_expired()
            raise

    async def _purge_expired(self) -> None:
        """Elimina items expirados de forma eficiente."""
        now = time()
        expired_count = 0
        
        async with self._lock:
            # Crear lista de keys expiradas
            expired_keys = [
                key for key, item in self._store.items()
                if item.expires_at is not None and item.expires_at <= now
            ]
            
            # Eliminar expirados
            for key in expired_keys:
                del self._store[key]
                expired_count += 1
        
        if expired_count > 0:
            logger.debug("🗑️  CacheManager: eliminados %d items expirados", expired_count)

    async def _enforce_memory_limits(self) -> None:
        """Aplica límites de memoria usando política LRU aproximada."""
        async with self._lock:
            if len(self._store) <= self._max_size:
                return
            
            # Ordenar por último acceso (usando access_count como proxy)
            items_to_remove = len(self._store) - self._max_size
            if items_to_remove <= 0:
                return
            
            # Ordenar por access_count (menos accedidos primero)
            sorted_items = sorted(
                self._store.items(),
                key=lambda x: x[1].access_count
            )
            
            # Eliminar los menos usados
            for key, _ in sorted_items[:items_to_remove]:
                del self._store[key]
                self._evictions += 1
            
            logger.debug("📦 CacheManager: evicted %d items por límite de memoria", items_to_remove)

    def _compress_data(self, data: Any) -> Any:
        """Comprime datos si está habilitado y es beneficioso."""
        if not self._enable_compression:
            return data
        
        # Solo comprimir si es string grande o bytes
        if isinstance(data, str) and len(data) > 1000:
            try:
                import zlib
                return zlib.compress(data.encode('utf-8'))
            except ImportError:
                pass
        elif isinstance(data, bytes) and len(data) > 1000:
            try:
                import zlib
                return zlib.compress(data)
            except ImportError:
                pass
        
        return data

    def _decompress_data(self, data: Any) -> Any:
        """Descomprime datos si están comprimidos."""
        if not self._enable_compression:
            return data
        
        try:
            import zlib
            if isinstance(data, bytes):
                try:
                    return zlib.decompress(data).decode('utf-8')
                except:
                    return data
        except ImportError:
            pass
        
        return data

    def _generate_key(self, *args, **kwargs) -> str:
        """Genera una clave única basada en los argumentos."""
        key_data = f"{args}{sorted(kwargs.items())}"
        return hashlib.md5(key_data.encode()).hexdigest()

    async def set(self, 
                  key: str, 
                  value: Any, 
                  ttl: Optional[float] = None,
                  compress: bool = False) -> None:
        """
        Guarda un valor en caché.
        
        :param key: clave única
        :param value: valor a almacenar
        :param ttl: tiempo de vida en segundos
        :param compress: forzar compresión
        """
        # Aplicar compresión si es necesario
        final_value = value
        if compress or self._enable_compression:
            final_value = self._compress_data(value)
        
        expires_at = None if ttl is None else time() + ttl
        
        async with self._lock:
            # Verificar límite de memoria antes de agregar
            if len(self._store) >= self._max_size:
                await self._enforce_memory_limits()
            
            self._store[key] = CacheItem(final_value, expires_at)

    async def get(self, key: str, default: Any = None) -> Any:
        """
        Obtiene un valor del caché.
        
        :param key: clave a buscar
        :param default: valor por defecto si no existe
        :return: valor almacenado o default
        """
        now = time()
        
        async with self._lock:
            item = self._store.get(key)
            
            if item is None:
                self._misses += 1
                return default
            
            # Verificar expiración
            if item.expires_at is not None and item.expires_at <= now:
                del self._store[key]
                self._misses += 1
                return default
            
            # Actualizar estadísticas de acceso
            item.access_count += 1
            self._hits += 1
            
            # Descomprimir si es necesario
            value = self._decompress_data(item.value)
            return value

    async def delete(self, key: str) -> bool:
        """Elimina un key del caché."""
        async with self._lock:
            if key in self._store:
                del self._store[key]
                return True
            return False

    async def delete_pattern(self, pattern: str) -> int:
        """
        Elimina todas las keys que coincidan con un patrón.
        
        :param pattern: patrón a buscar (usando 'in')
        :return: número de keys eliminadas
        """
        async with self._lock:
            matching_keys = [k for k in self._store.keys() if pattern in k]
            for key in matching_keys:
                del self._store[key]
            
            return len(matching_keys)

    async def clear(self) -> None:
        """Limpia todo el caché y reinicia estadísticas."""
        async with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0

    async def size(self) -> int:
        """Número de items en caché."""
        async with self._lock:
            return len(self._store)

    async def keys(self, pattern: str = "") -> List[str]:
        """
        Lista de keys que coinciden con patrón.
        
        :param pattern: patrón para filtrar keys
        :return: lista de keys
        """
        async with self._lock:
            if pattern:
                return [k for k in self._store.keys() if pattern in k]
            return list(self._store.keys())

    async def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas del caché."""
        async with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = (self._hits / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'size': len(self._store),
                'hits': self._hits,
                'misses': self._misses,
                'evictions': self._evictions,
                'hit_rate': round(hit_rate, 2),
                'max_size': self._max_size
            }

    async def get_or_set(self, 
                         key: str, 
                         factory_coro: Callable, 
                         ttl: Optional[float] = None,
                         compress: bool = False) -> Any:
        """
        Obtiene valor o ejecuta factory_coro si no existe.
        
        :param key: clave del caché
        :param factory_coro: corrutina para generar el valor
        :param ttl: tiempo de vida
        :param compress: comprimir datos
        :return: valor del caché
        """
        # Intentar obtener valor existente
        value = await self.get(key)
        if value is not None:
            return value

        # Doble verificación bajo lock para evitar stampede
        async with self._lock:
            item = self._store.get(key)
            if item is not None:
                now = time()
                if item.expires_at is None or item.expires_at > now:
                    item.access_count += 1
                    self._hits += 1
                    return self._decompress_data(item.value)
                else:
                    del self._store[key]

        # Generar nuevo valor (fuera del lock)
        try:
            result = await factory_coro()
            await self.set(key, result, ttl=ttl, compress=compress)
            return result
        except Exception as e:
            logger.error("❌ Error en factory_coro para key %s: %s", key, e)
            raise

    async def exists(self, key: str) -> bool:
        """Verifica si una key existe y no está expirada."""
        now = time()
        async with self._lock:
            item = self._store.get(key)
            if item is None:
                return False
            if item.expires_at is not None and item.expires_at <= now:
                del self._store[key]
                return False
            return True

    async def ttl(self, key: str) -> Optional[float]:
        """
        Obtiene el TTL restante de una key.
        
        :param key: clave a verificar
        :return: segundos restantes o None si no expira
        """
        now = time()
        async with self._lock:
            item = self._store.get(key)
            if item is None or item.expires_at is None:
                return None
            
            if item.expires_at <= now:
                del self._store[key]
                return None
            
            return item.expires_at - now

    async def increment(self, key: str, value: int = 1, ttl: Optional[float] = None) -> int:
        """
        Incrementa un valor numérico en el caché.
        
        :param key: clave del contador
        :param value: valor a incrementar
        :param ttl: nuevo TTL (opcional)
        :return: nuevo valor
        """
        async with self._lock:
            current = await self.get(key, 0)
            new_value = current + value
            await self.set(key, new_value, ttl=ttl)
            return new_value

# Instancia global para uso fácil
_cache_instance: Optional[CacheManager] = None

async def get_cache_manager() -> CacheManager:
    """Obtiene la instancia global del CacheManager."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = CacheManager()
        await _cache_instance.init()
    return _cache_instance

async def close_cache_manager() -> None:
    """Cierra la instancia global del CacheManager."""
    global _cache_instance
    if _cache_instance is not None:
        await _cache_instance.close()
        _cache_instance = None
