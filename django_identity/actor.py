from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class ActorContext:
    """
    Инициатор действия (контекст запроса).

    Представляет субъект, от имени которого выполняется запрос.
    """
    
    actor_type: Literal["human", "system"]
    issuer: str
    subject: str | None