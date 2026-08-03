from abc import ABC, abstractmethod

from django_identity.actor import ActorContext


class AuthenticationProvider(ABC):
    """
    Базовый провайдер аутентификации.

    Провайдер отвечает за проверку учетных данных
    и возвращает ActorContext.
    """

    name: str

    @classmethod
    @abstractmethod
    def authenticate(
        cls,
        credentials,
    ) -> ActorContext:
        """
        Выполняет аутентификацию пользователя.

        Raises:
            InvalidCredentials
        """
        raise NotImplementedError
