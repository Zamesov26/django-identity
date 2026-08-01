import logging
from typing import Any

from django.http import HttpRequest

from django_identity.models import IdentitySecurityEvent

logger = logging.getLogger(__name__)


def _get_ip(request: HttpRequest | None) -> str | None:
    if not request:
        return None

    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()

    return request.META.get("REMOTE_ADDR")


def _get_user_agent(request: HttpRequest | None) -> str | None:
    if not request:
        return None

    return request.META.get("HTTP_USER_AGENT")


def log_security_event(
    *,
    event_type: str,
    request: HttpRequest | None = None,
    external_user_id: str | None = None,
    token: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """
    Зафиксировать событие безопасности.
    Никогда не бросает исключений.
    """

    try:
        IdentitySecurityEvent.objects.create(
            event_type=event_type,
            external_user_id=external_user_id,
            token=token,
            ip_address=_get_ip(request),
            user_agent=_get_user_agent(request),
            extra=extra or {},
        )
    except Exception as e:
        logger.exception(e)
