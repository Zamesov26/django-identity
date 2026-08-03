from django.conf import settings
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from django_identity.exceptions import InvalidCredentials, InvalidRefreshToken
from django_identity.services.refresh_token import RefreshTokenService
from users.identity.authentication import LoginService
from users.identity.serializers import LoginSerializer


class LoginAPIView(APIView):
    """
    Выполняет вход пользователя.
    """

    authentication_classes = []
    permission_classes = []

    @extend_schema(
        request=LoginSerializer,
        tags=["Authentication"],
        summary="Login",
        description=(
            "Выполняет аутентификацию пользователя и возвращает новую пару токенов."
        ),
        responses={
            200: {
                "type": "object",
                "properties": {
                    "access_token": {
                        "type": "string",
                    },
                    "expires_at": {
                        "type": "string",
                        "format": "date-time",
                    },
                },
            },
            401: OpenApiResponse(
                description="Invalid credentials",
            ),
        },
    )
    def post(self, request):
        serializer = LoginSerializer(
            data=request.data,
        )
        serializer.is_valid(
            raise_exception=True,
        )

        try:
            tokens = LoginService.authenticate(
                serializer.to_credentials(),
            )

        except InvalidCredentials:
            #
            # Здесь проект может писать аудит,
            # отправлять события безопасности,
            # увеличивать счетчик неудачных попыток и т.д.
            #
            return Response(
                {
                    "detail": "Invalid credentials.",
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        response = Response(
            {
                "access_token": tokens.access_token,
                "expires_at": tokens.expires_at,
            },
            status=status.HTTP_200_OK,
        )

        response.set_cookie(
            key="refresh",
            value=tokens.refresh_token,
            httponly=True,
            secure=not settings.DEBUG,
            samesite="Strict",
            path="/api/v1/auth/",
            max_age=settings.IDENTITY["JWT"]["REFRESH_TTL"],
        )

        return response


class RefreshAPIView(APIView):
    """
    Выпускает новую пару access/refresh токенов.
    """

    authentication_classes = []
    permission_classes = []

    @extend_schema(
        tags=["Authentication"],
        summary="Refresh access token",
        description=("Обновляет access-токен по refresh-токену из HttpOnly cookie."),
        responses={
            200: {
                "type": "object",
                "properties": {
                    "access_token": {
                        "type": "string",
                    },
                    "expires_at": {
                        "type": "string",
                        "format": "date-time",
                    },
                },
            },
            401: OpenApiResponse(
                description="Invalid refresh token",
            ),
        },
    )
    def post(self, request):
        refresh_token = request.COOKIES.get("refresh")

        if refresh_token is None:
            return Response(
                {
                    "detail": "Refresh token not found.",
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            tokens = RefreshTokenService.rotate(
                refresh_token,
            )

        except InvalidRefreshToken as exc:
            #
            # Здесь проект может логировать
            # подозрительные попытки refresh.
            #
            return Response(
                {
                    "detail": str(exc),
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        response = Response(
            {
                "access_token": tokens.access_token,
                "expires_at": tokens.expires_at,
            }
        )

        response.set_cookie(
            key="refresh",
            value=tokens.refresh_token,
            httponly=True,
            secure=not settings.DEBUG,
            samesite="Strict",
            path="/api/v1/auth/",
            max_age=settings.IDENTITY["JWT"]["REFRESH_TTL"],
        )

        return response


class LogoutAPIView(APIView):
    """
    Завершает текущую пользовательскую сессию.
    """

    @extend_schema(
        tags=["Authentication"],
        summary="Logout",
        description=(
            "Завершает текущую пользовательскую сессию.\n\n"
            "- Требует аутентификации.\n"
            "- Отзывает refresh-токен.\n"
            "- Удаляет refresh-cookie."
        ),
        responses={
            204: OpenApiResponse(
                description="Successfully logged out.",
            ),
            401: OpenApiResponse(
                description="Authentication required.",
            ),
        },
    )
    def post(self, request):
        refresh_token = request.COOKIES.get("refresh")

        if refresh_token:
            RefreshTokenService.revoke(
                refresh_token,
            )

        response = Response(
            status=status.HTTP_204_NO_CONTENT,
        )

        response.delete_cookie(
            key="refresh",
            path="/api/v1/auth/",
        )

        return response


class LogoutAllAPIView(APIView):
    """
    Завершает все активные пользовательские сессии.
    """

    @extend_schema(
        tags=["Authentication"],
        summary="Logout from all devices",
        description=(
            "Завершает все активные сессии пользователя.\n\n"
            "- Требует аутентификации.\n"
            "- Отзывает все refresh-токены пользователя.\n"
            "- Удаляет refresh-cookie текущего браузера."
        ),
        responses={
            204: OpenApiResponse(
                description="Successfully logged out from all devices.",
            ),
            401: OpenApiResponse(
                description="Authentication required.",
            ),
        },
    )
    def post(self, request):
        RefreshTokenService.revoke_all(
            request.identity.actor,
        )

        response = Response(
            status=status.HTTP_204_NO_CONTENT,
        )

        response.delete_cookie(
            key="refresh",
            path="/api/v1/auth/",
        )

        return response
