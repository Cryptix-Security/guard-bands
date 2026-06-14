from abc import ABC, abstractmethod
from app.audit import AuditEvent


class AuditSink(ABC):
    @abstractmethod
    async def emit(self, event: AuditEvent) -> None: ...

    async def startup(self) -> None:
        pass

    async def shutdown(self) -> None:
        pass
