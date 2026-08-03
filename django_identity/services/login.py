from django_identity.authentication.base import AuthenticationProvider
from django_identity.services.access_token import AccessTokenService
from django_identity.services.refresh_token import RefreshTokenService
from django_identity.tokens import AuthTokens


class LoginService:
    """
    Выполняет вход пользователя.

    Сервис не знает, каким способом происходит проверка учетных
    данных (Django User, LDAP, OAuth и т.д.).

    За проверку отвечает AuthenticationProvider.
    """

    @classmethod
    def login(
        cls,
        credentials,
    ) -> AuthTokens:
        """
        Выполняет аутентификацию и выпускает новую пару токенов.
        """

        actor = AuthenticationProvider.authenticate(
            credentials,
        )

        refresh = RefreshTokenService.issue(
            actor,
        )

        access = AccessTokenService.issue(
            actor,
        )

        return AuthTokens(
            access_token=access,
            refresh_token=refresh.token,
            expires_at=AccessTokenService.expires_at(),
        )
