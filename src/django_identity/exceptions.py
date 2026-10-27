class IdentityError(Exception):
    """
    Базовое исключение библиотеки django_identity.
    """

    code = "identity_error"

    def __init__(self, message: str | None = None):
        super().__init__(message or self.code)


class AuthenticationError(IdentityError):
    """
    Ошибка аутентификации.

    Credential существует, но не прошло проверку.
    """

    code = "authentication_error"


class UnsupportedCredentialScheme(IdentityError):
    """
    Для указанной схемы credential отсутствует провайдер.
    """

    code = "unsupported_scheme"


class InvalidCredential(AuthenticationError):
    """
    Credential имеет неверный формат или подпись.
    """

    code = "invalid_credential"


class CredentialExpired(AuthenticationError):
    """
    Срок действия credential истёк.
    """

    code = "credential_expired"


class InvalidRefreshToken(AuthenticationError):
    """
    Refresh-токен недействителен.

    Используется в случаях:
    - токен не найден;
    - токен уже был отозван;
    - срок действия токена истёк.
    """

    code = "invalid_refresh_token"


class InvalidCredentials(AuthenticationError):
    """
    Переданы неверные учетные данные для входа.

    Например:
    - неверный логин;
    - неверный пароль;
    - пользователь не существует.
    """

    code = "invalid_credentials"


class IdentityConfigurationError(IdentityError):
    """
    Ошибка конфигурации библиотеки.
    """

    code = "identity_configuration_error"
