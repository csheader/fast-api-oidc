from typing import Any, Optional, Protocol, runtime_checkable, Dict

@runtime_checkable
class CacheProtocol(Protocol):
    def add_token(self, token: str, value: Any) -> None:
        ...

    def get_token(self, token: str) -> Optional[Any]:
        ...

    def remove_token(self, token: str) -> bool:
        ...

    def clear(self) -> None:
        ...

    def list_tokens(self, page: int = 1, page_size: int = 10) -> Dict[str, Any]:
        ...