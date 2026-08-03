import secrets
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils.timezone import now

from django_identity.actor import ActorContext
from django_identity.exceptions import InvalidRefreshToken
from django_identity.models import IdentityRefreshToken
from django_identity.services.access_token import AccessTokenService
from django_identity.tokens import AuthTokens


class RefreshTokenService:
    """
    Управление refresh-токенами.

    Refresh-токен является непрозрачным (opaque) случайным значением,
    которое хранится в базе данных и используется для выпуска
    новых access-токенов.
    """

    @classmethod
    def issue(cls, actor: ActorContext) -> IdentityRefreshToken:
        """
        Выпускает новый refresh-токен.
        """
        return IdentityRefreshToken.objects.create(
            token=secrets.token_urlsafe(48),
            issuer=actor.issuer,
            subject=actor.subject,
            actor_type=actor.actor_type,
            expires_at=cls._expires_at(),
        )

    @classmethod
    def rotate(cls, token: str) -> AuthTokens:
        """
        Выполняет ротацию refresh-токена.

        Старый токен отзывается.
        Выпускаются новый refresh и новый access.
        """

        refresh = cls._get_active(token)

        cls._revoke(refresh)
        new_refresh = cls.issue(refresh.actor)
        access = AccessTokenService.issue(refresh.actor)

        return AuthTokens(
            access_token=access,
            refresh_token=new_refresh.token,
            expires_at=AccessTokenService.expires_at(),
        )

    @classmethod
    def revoke(cls, token: str | None) -> None:
        """
        Отзывает refresh-токен.
        """

        if not token:
            return

        IdentityRefreshToken.objects.filter(
            token=token,
            is_active=True,
        ).update(
            is_active=False,
        )

    @classmethod
    def revoke_all(cls, actor: ActorContext) -> int:
        """
        Отзывает все refresh-токены актора.
        """

        return IdentityRefreshToken.objects.filter(
            issuer=actor.issuer,
            subject=actor.subject,
            is_active=True,
        ).update(
            is_active=False,
        )

    @classmethod
    @transaction.atomic
    def _get_active(cls, token: str) -> IdentityRefreshToken:

        try:
            refresh = IdentityRefreshToken.objects.select_for_update().get(token=token)

        except IdentityRefreshToken.DoesNotExist:
            raise InvalidRefreshToken(
                "Refresh token not found.",
            ) from None

        if not refresh.is_active:
            raise InvalidRefreshToken(
                "Refresh token revoked.",
            )

        if refresh.is_expired():
            refresh.revoke()

            raise InvalidRefreshToken(
                "Refresh token expired.",
            )

        return refresh

    @staticmethod
    def _revoke(refresh: IdentityRefreshToken) -> None:
        refresh.revoke()

    @staticmethod
    def _expires_at():
        return now() + timedelta(
            seconds=settings.IDENTITY["JWT"]["REFRESH_TTL"],
        )
