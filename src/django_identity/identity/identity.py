from dataclasses import dataclass
from typing import Any

from django_identity.actor import ActorContext
from django_identity.scopes import decode_scope


@dataclass(slots=True)
class Identity:
    """
    Результат успешной идентификации запроса.

    Identity содержит информацию, полученную после проверки
    учетных данных, и используется middleware для заполнения
    объекта request.

    Attributes:
        actor:
            Универсальное представление инициатора запроса.

        user:
            Django User, если инициатором является человек.
            Для системных акторов может быть None.

        claims:
            Дополнительные данные, полученные в процессе
            идентификации (например JWT claims).
    """

    actor: ActorContext
    claims: dict[str, Any]

    @property
    def scopes(self) -> list[str]:
        """Вернуть список scopes из проверенного JWT claim `scope`."""
        return decode_scope(self.claims.get("scope"))
