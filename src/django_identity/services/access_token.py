from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

import jwt
from django.conf import settings
from django.utils.timezone import now

from django_identity.actor import ActorContext
from django_identity.identity.identity import Identity
from django_identity.scopes import encode_scopes

PRIVATE_KEY_PATH = Path(settings.IDENTITY["JWT"]["PRIVATE_KEY_PATH"])


@lru_cache(maxsize=1)
def load_private_key() -> str:
    """
    Загружает приватный ключ для подписи JWT.
    Используется ТОЛЬКО если сервис сам является issuer.
    """
    if not PRIVATE_KEY_PATH.exists():
        raise RuntimeError(f"JWT private key not found: {PRIVATE_KEY_PATH}")
    return PRIVATE_KEY_PATH.read_text()


class AccessTokenService:
    """
    Сервис выпуска JWT access-токенов.
    """

    MANAGED_CLAIMS = {
        "iss",
        "aud",
        "sub",
        "actor_type",
        "exp",
        "iat",
        "act",
        "scope",
    }

    @classmethod
    def issue(
        cls,
        actor: ActorContext,
        *,
        audience: str | None = None,
        scopes: list[str] | None = None,
        **claims,
    ) -> str:
        """
        Выпускает новый JWT access-токен.
        """
        cls._validate_custom_claims(claims)

        payload = cls._build_payload(actor, audience=audience, scopes=scopes)
        payload.update(claims)
        return cls._encode(payload)

    @classmethod
    def issue_delegated(
        cls,
        identity: Identity,
        *,
        audience: str,
        scopes: list[str] | None = None,
        **claims,
    ) -> str:
        """
        Выпускает системный токен для вызова другого сервиса.

        Исходный subject, если он есть, сохраняется, а история сервисов,
        действовавших от его имени, записывается в стандартный claim ``act``.
        """
        cls._validate_custom_claims(claims)

        actor = ActorContext(
            actor_type="system",
            issuer=settings.IDENTITY["SERVICE_NAME"],
            subject=identity.actor.subject,
        )
        payload = cls._build_payload(actor, audience=audience, scopes=scopes)
        payload["act"] = cls._build_actor_claim(identity)
        payload.update(claims)
        return cls._encode(payload)

    @staticmethod
    def _encode(payload: dict[str, Any]) -> str:
        return jwt.encode(
            payload,
            load_private_key(),
            algorithm=settings.IDENTITY["JWT"]["ALGORITHM"],
            headers={"typ": "at+jwt"},
        )

    @classmethod
    def _validate_custom_claims(cls, claims: dict[str, Any]) -> None:
        """Запретить подмену claims, которыми управляет библиотека."""
        conflicting_claims = cls.MANAGED_CLAIMS.intersection(claims)
        if conflicting_claims:
            names = ", ".join(sorted(conflicting_claims))
            raise ValueError(f"Cannot override managed claims: {names}.")

    @classmethod
    def expires_at(cls) -> datetime:
        """
        Возвращает время истечения access-токена.
        """
        return now() + timedelta(
            seconds=settings.IDENTITY["JWT"]["ACCESS_TTL"],
        )

    @classmethod
    def _build_payload(
        cls,
        actor: ActorContext,
        *,
        audience: str | None = None,
        scopes: list[str] | None = None,
    ) -> dict:

        issued_at = now()
        expires_at = issued_at + timedelta(
            seconds=settings.IDENTITY["JWT"]["ACCESS_TTL"],
        )

        payload = {
            "iss": settings.IDENTITY["SERVICE_NAME"],
            "aud": audience or settings.IDENTITY["SERVICE_NAME"],
            "actor_type": actor.actor_type,
            "iat": issued_at,
            "exp": expires_at,
        }

        if actor.subject is not None:
            payload["sub"] = actor.subject

        scope = encode_scopes(scopes)
        if scope is not None:
            payload["scope"] = scope

        return payload

    @staticmethod
    def _build_actor_claim(identity: Identity) -> dict[str, Any]:
        actor_claim: dict[str, Any] = {
            "sub": settings.IDENTITY["SERVICE_NAME"],
        }
        previous_actor = identity.claims.get("act")

        if isinstance(previous_actor, dict):
            actor_claim["act"] = previous_actor
        elif identity.actor.actor_type == "system":
            # Поддерживаем входящие токены без act: их issuer является
            # предыдущим системным актором в цепочке делегирования.
            actor_claim["act"] = {"sub": identity.actor.issuer}

        return actor_claim
