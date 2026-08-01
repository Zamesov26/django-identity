from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path

import jwt
from django.conf import settings
from django.utils.timezone import now

from django_identity.actor import ActorContext

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
    
    @classmethod
    def issue(
        cls,
        actor: ActorContext,
        **claims,
    ) -> str:
        """
        Выпускает новый JWT access-токен.
        """
        payload = cls._build_payload(actor)
        payload.update(claims)
        return jwt.encode(
            payload,
            load_private_key(),
            algorithm=settings.IDENTITY["JWT"]["ALGORITHM"],
        )
    
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
    ) -> dict:
        
        expires_at = cls.expires_at()
        
        return {
            "iss": settings.IDENTITY["JWT"]["ISSUER"],
            "aud": settings.IDENTITY["JWT"]["AUDIENCE"],
            "sub": actor.subject,
            "actor_type": actor.actor_type,
            "exp": expires_at,
        }
