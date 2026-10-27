from abc import abstractmethod, ABC

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser
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
    """
    Возвращает зарегистрированный UserResolver.
    """
    
    return import_string(
        settings.IDENTITY["JWT"]["USER_RESOLVER"],
    )