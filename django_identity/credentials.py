from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class Credential:
    """
    Данные для последующей идентификации.

    scheme:
        Тип схемы аутентификации, например:
        - Bearer
        - ApiKey
        - Basic

    value:
        Значение credential без префикса схемы.
    """

    scheme: str
    value: str


@dataclass(frozen=True, slots=True)
class UsernamePasswordCredentials:
    """
    Учетные данные для аутентификации по имени пользователя
    и паролю.
    """

    username: str
    password: str
