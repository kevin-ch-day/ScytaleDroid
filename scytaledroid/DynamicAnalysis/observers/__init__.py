"""Observer implementations for dynamic analysis."""

from .base import Observer, ObserverHandle, ObserverResult
from .network_capture import NetworkCaptureObserver
from .proxy_capture import ProxyCaptureObserver
from .system_logs import SystemLogObserver

__all__ = [
    "Observer",
    "ObserverHandle",
    "ObserverResult",
    "NetworkCaptureObserver",
    "ProxyCaptureObserver",
    "SystemLogObserver",
]
