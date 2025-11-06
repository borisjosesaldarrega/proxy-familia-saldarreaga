# core/cache_manager.py
import asyncio
import logging
from typing import Any, Optional
from time import time

logger = logging.getLogger(__name__)

class CacheItem:
    __slots__ = ("value", "expires_at")
    def __init__(self, value: Any, expires_at: Optional[float]):
        self.value = value
        self.expires_at = expires_at

class CacheManager:
    """
    CacheManager asíncrono simple para proxy.
    - Soporta TTL en segundos (None = sin expiración).
    - Concurrencia protegida con Lock.
    - Limpieza periódica de items expirados.
    """

    def __init__(self, cleanup_interval: float = 30.0):
        """
        :param cleanup_interval: cada cuántos segundos se ejecuta el recolector de basura.
        """
        self._store: dict[str, CacheItem] = {}
        self._lock = asyncio.Lock()
        self._cleanup_interval = cleanup_interval
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False

    async def init(self) -> None:
        """Inicializa recursos y lanza tarea de limpieza."""
        if not self._running:
            self._running = True
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info("CacheManager iniciado (cleanup every %ss)", self._cleanup_interval)

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
            logger.info("CacheManager detenido")

    async def _cleanup_loop(self) -> None:
        """Loop que periódicamente borra keys expiradas."""
        try:
            while self._running:
                await asyncio.sleep(self._cleanup_interval)
                await self._purge_expired()
        except asyncio.CancelledError:
            # Limpiar una última vez al cancelar
            await self._purge_expired()
            raise

    async def _purge_expired(self) -> None:
        now = time()
        to_delete = []
        async with self._lock:
            for k, item in self._store.items():
                if item.expires_at is not None and item.expires_at <= now:
                    to_delete.append(k)
            for k in to_delete:
                del self._store[k]
        if to_delete:
            logger.debug("CacheManager: eliminado %d items expirados", len(to_delete))

    async def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """
        Guarda un valor en caché.
        :param key: clave (string)
        :param value: valor (cualquier objeto serializable en memoria)
        :param ttl: tiempo en segundos para expirar. None = no expira.
        """
        expires_at = None if ttl is None else time() + ttl
        async with self._lock:
            self._store[key] = CacheItem(value, expires_at)

    async def get(self, key: str, default: Any = None) -> Any:
        """
        Obtiene un valor. Retorna default si no existe o está expirado.
        """
        now = time()
        async with self._lock:
            item = self._store.get(key)
            if item is None:
                return default
            if item.expires_at is not None and item.expires_at <= now:
                # expirado: quitar y devolver default
                del self._store[key]
                return default
            return item.value

    async def delete(self, key: str) -> bool:
        """Elimina un key; retorna True si existía."""
        async with self._lock:
            if key in self._store:
                del self._store[key]
                return True
            return False

    async def clear(self) -> None:
        """Limpia todo el caché."""
        async with self._lock:
            self._store.clear()

    async def size(self) -> int:
        """Número de items actualmente (incluye los no-expirados)."""
        async with self._lock:
            return len(self._store)

    async def keys(self) -> list[str]:
        """Lista de keys (no garantiza orden)."""
        async with self._lock:
            return list(self._store.keys())

    # Helper útil para caches de respuestas HTTP
    async def get_or_set(self, key: str, factory_coro, ttl: Optional[float] = None):
        """
        Si existe devuelve, si no ejecuta factory_coro() (coroutine), guarda resultado y lo retorna.
        factory_coro debe ser una coroutine callable sin argumentos.
        """
        value = await self.get(key, default=None)
        if value is not None:
            return value
        # bloquear creación para evitar stampede: verificamos doblemente dentro de lock
        async with self._lock:
            item = self._store.get(key)
            if item is not None:
                # otro coroutine ya creó el valor
                now = time()
                if item.expires_at is None or item.expires_at > now:
                    return item.value
                else:
                    del self._store[key]

            # crear valor fuera del lock para no bloquear mucho tiempo
        result = await factory_coro()
        await self.set(key, result, ttl=ttl)
        return result
