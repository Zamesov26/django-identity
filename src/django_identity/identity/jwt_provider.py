import jwt
from django.conf import settings
from django.http import HttpRequest

from django_identity.actor import ActorContext
from django_identity.credentials import Credential
from django_identity.exceptions import CredentialExpired, InvalidCredential
from django_identity.identity.base import IdentityProvider
from django_identity.identity.identity import Identity
from django_identity.identity.registry import IdentityProviderRegistry
from django_identity.models import IdentityTrustedIssuer
from django_identity.scopes import decode_scope


@IdentityProviderRegistry.register
class JWTIdentityProvider(IdentityProvider):
    """
    Провайдер идентификации по Bearer JWT.
    """

    scheme = "Bearer"

    @classmethod
    def authenticate(
        cls,
        request: HttpRequest,
        credential: Credential,
    ) -> Identity:
        """
        Проверяет JWT и возвращает Identity.
        """

        cls._validate_token_type(credential.value)
        claims = cls._decode_unverified(credential.value)
        issuer = cls._get_trusted_issuer(claims)
        claims = cls._verify(credential.value, issuer)
        cls._validate_scope(claims)
        actor = cls._build_actor(claims, issuer)

        return Identity(
            actor=actor,
            claims=claims,
        )

    @staticmethod
    def _validate_token_type(token: str) -> None:
        """Проверить тип access-токена с поддержкой legacy JWT."""
        try:
            token_type = jwt.get_unverified_header(token).get("typ")
        except jwt.PyJWTError as exc:
            raise InvalidCredential(str(exc)) from exc

        if token_type not in (None, "JWT", "at+jwt"):
            raise InvalidCredential("Invalid token type.")

    @staticmethod
    def _decode_unverified(
        token: str,
    ) -> dict:
        return jwt.decode(
            token,
            options={
                "verify_signature": False,
            },
        )

    @staticmethod
    def _get_trusted_issuer(
        claims: dict,
    ) -> IdentityTrustedIssuer:
        issuer = claims.get("iss")

        if not issuer:
            raise InvalidCredential("Missing issuer.")

        try:
            return IdentityTrustedIssuer.objects.get(
                issuer=issuer,
                is_active=True,
            )
        except IdentityTrustedIssuer.DoesNotExist:
            raise InvalidCredential(f'Unknown issuer "{issuer}".') from None

    @staticmethod
    def _verify(
        token: str,
        issuer: IdentityTrustedIssuer,
    ) -> dict:
        try:
            return jwt.decode(
                token,
                key=issuer.public_key,
                algorithms=[issuer.algorithm],
                audience=settings.IDENTITY["SERVICE_NAME"],
                issuer=issuer.issuer,
                options={
                    "require": [
                        "exp",
                        "iss",
                        "aud",
                    ],
                },
            )

        except jwt.ExpiredSignatureError as exc:
            raise CredentialExpired("Credential expired.") from exc

        except jwt.PyJWTError as exc:
            raise InvalidCredential(
                str(exc),
            ) from exc

    @staticmethod
    def _build_actor(
        claims: dict,
        issuer: IdentityTrustedIssuer,
    ) -> ActorContext:

        actor_type = claims.get("actor_type")

        if actor_type not in ("human", "system"):
            raise InvalidCredential("Invalid actor_type.")

        if actor_type == "human":
            if not issuer.allow_human:
                raise InvalidCredential("Issuer cannot authenticate human actors.")

            subject = claims.get("sub")

            if not subject:
                raise InvalidCredential("Missing subject.")

        else:
            if not issuer.allow_system:
                raise InvalidCredential("Issuer cannot authenticate system actors.")

            subject = claims.get("sub")

        return ActorContext(
            actor_type=actor_type,
            issuer=claims["iss"],
            subject=subject,
        )

    @staticmethod
    def _validate_scope(claims: dict) -> None:
        """Проверить формат необязательного claim `scope`."""
        try:
            decode_scope(claims.get("scope"))
        except ValueError as exc:
            raise InvalidCredential(str(exc)) from exc
