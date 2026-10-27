from abc import ABC, abstractmethod

from django.http import HttpRequest

from django_identity.credentials import Credential
from django_identity.identity.identity import Identity


class IdentityProvider(ABC):
    """
    Базовый провайдер идентификации.

    Провайдер отвечает за проверку credential и построение
    объекта Identity.

    Каждый провайдер обслуживает одну схему аутентификации
    (Bearer, ApiKey, Basic и т.д.).
    """

    #: HTTP Authorization Scheme
    scheme: str

    @classmethod
    @abstractmethod
    def authenticate(
        cls,
        request: HttpRequest,
        credential: Credential,
    ) -> Identity:
        """
        Проверяет credential и возвращает Identity.

        Raises:
            AuthenticationError:
                Если credential не прошло проверку.
        """
        raise NotImplementedError
