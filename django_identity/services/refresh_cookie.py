from django.conf import settings
from django.http import HttpResponse


class RefreshCookie:

    @classmethod
    def set(
        cls,
        response: HttpResponse,
        token: str,
    ) -> None:
        response.set_cookie(
            key="refresh",
            value=token,
            httponly=True,
            secure=not settings.DEBUG,
            samesite="Strict",
            path=settings.IDENTITY["JWT"]["COOKIE_PATH"],
            max_age=settings.IDENTITY["JWT"]["REFRESH_TTL"],
        )

    @classmethod
    def delete(
        cls,
        response: HttpResponse,
    ) -> None:
        response.delete_cookie(
            key="refresh",
            path=settings.IDENTITY["JWT"]["COOKIE_PATH"],
        )