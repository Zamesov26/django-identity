import time

import pytest

from django_identity.actor import ActorContext
from django_identity.identity.identity import Identity


@pytest.fixture
def system_actor() -> ActorContext:
    """Вернуть системного актора без связанного пользователя."""
    return ActorContext(
        actor_type="system",
        issuer="PMC-JWT",
        subject=None,
    )


@pytest.fixture
def system_identity(system_actor: ActorContext) -> Identity:
    """Вернуть проверенную системную identity без claim `sub`."""
    return Identity(
        actor=system_actor,
        claims={
            "iss": "PMC-JWT",
            "aud": "TECH-API",
            "actor_type": "system",
            "exp": int(time.time()) + 3_600,
        },
    )
