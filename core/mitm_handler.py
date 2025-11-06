import asyncio
import logging

logger = logging.getLogger(__name__)

class MITMHandler:
    """
    Stub temporal de MITMHandler.
    Reemplaza este archivo por la implementación real cuando la tengas.
    """
    def __init__(self, config=None):
        self.config = config
        self._running = False

    async def start(self):
        logger.info("MITMHandler: start (stub)")
        self._running = True
        # simulación de tarea (no bloqueante)
        await asyncio.sleep(0)

    async def stop(self):
        logger.info("MITMHandler: stop (stub)")
        self._running = False
        await asyncio.sleep(0)
