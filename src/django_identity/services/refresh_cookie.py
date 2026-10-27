from django.conf import settings
from django.http import HttpResponse


class JWTCookie:
    
    @classmethod
    def set_access(
        cls,
        response: HttpResponse,
        token: str,
    ) -> None:
        response.set_cookie(
            key="access",
            value=token,
            httponly=True,
            secure=not settings.DEBUG,
            samesite="Strict",
            path=settings.IDENTITY["JWT"]["ACCESS_COOKIE_PATH"],
            max_age=settings.IDENTITY["JWT"]["ACCESS_TTL"],
        )
    
    @classmethod
    def set_refresh(
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
            path=settings.IDENTITY["JWT"]["REFRESH_COOKIE_PATH"],
            max_age=settings.IDENTITY["JWT"]["REFRESH_TTL"],
        )
    
    @classmethod
    def delete_access(
        cls,
        response: HttpResponse,
    ) -> None:
        response.delete_cookie(
            key="access",
            path=settings.IDENTITY["JWT"]["ACCESS_COOKIE_PATH"],
        )
    
    @classmethod
    def delete_refresh(
        cls,
        response: HttpResponse,
    ) -> None:
        response.delete_cookie(
            key="refresh",
            path=settings.IDENTITY["JWT"]["REFRESH_COOKIE_PATH"],
        )
    
    @classmethod
    def delete_all(
        cls,
        response: HttpResponse,
    ) -> None:
        cls.delete_access(response)
        cls.delete_refresh(response)
