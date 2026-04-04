import time
import threading
from abc import ABC, abstractmethod
from typing import Callable, Optional

class BaseCollector(ABC):
    """
    Tüm log toplayıcıların (collector) türetileceği temel sınıf.
    Sisteme log akışını asenkron olarak sağlar.
    """
    def __init__(self, name: str):
        self.name = name
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.on_log_received: Optional[Callable[[dict], None]] = None

    def start(self, callback: Callable[[dict], None]):
        """Collector'ı başlatır ve log geldiğinde callback fonksiyonunu çağırır."""
        self.on_log_received = callback
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Toplayıcıyı durdurur."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=1.0)

    @abstractmethod
    def _run_loop(self):
        """Alt sınıflar bu metodu ezerek log üretim/dinleme döngüsünü kuracaklar."""
        pass
