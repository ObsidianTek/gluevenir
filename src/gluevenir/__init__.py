"""Public Gluevenir foundation API."""

from __future__ import annotations

from ._ports import (
    MemoryActionGateway,
    MemoryContext,
    MemoryOperation,
    RecallRequest,
)

__all__ = ["Gluevenir", "MemoryContext", "RecallRequest"]


class Gluevenir[GatewayOutputT]:
    """Small SDK facade whose operations always enter the configured gateway."""

    __slots__ = ("__gateway",)

    def __init__(self, *, gateway: MemoryActionGateway[GatewayOutputT]) -> None:
        self.__gateway = gateway

    def recall(
        self, request: RecallRequest, *, context: MemoryContext
    ) -> GatewayOutputT:
        """Delegate recall to the Memory Action Gateway without adapter access."""

        return self.__gateway.execute(
            operation=MemoryOperation.RECALL,
            payload=request,
            context=context,
        )
