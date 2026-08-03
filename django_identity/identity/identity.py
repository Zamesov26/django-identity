from dataclasses import dataclass
from typing import Any

from django_identity.actor import ActorContext


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
