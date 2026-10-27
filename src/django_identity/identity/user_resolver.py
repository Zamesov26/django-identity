from abc import ABC, abstractmethod

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from django_identity.identity.identity import Identity


class UserResolver(ABC):
    @abstractmethod
    def resolve(
        self,
        identity: Identity,
    ) -> AbstractBaseUser | None:
        """
        Возвращает пользователя, соответствующего Identity.

        Если пользователь не найден, возвращает None.
        """


def get_user_resolver() -> UserResolver:
    """Создать настроенный resolver пользователей."""
    resolver_class = import_string(
        settings.IDENTITY["JWT"]["USER_RESOLVER"],
    )

    if not isinstance(resolver_class, type) or not issubclass(
        resolver_class,
        UserResolver,
    ):
        raise ImproperlyConfigured(
            'IDENTITY["JWT"]["USER_RESOLVER"] must point to '
            "a UserResolver subclass."
        )

    try:
        return resolver_class()
    except TypeError as exc:
        raise ImproperlyConfigured(
            'IDENTITY["JWT"]["USER_RESOLVER"] must be instantiable '
            "without arguments."
        ) from exc
