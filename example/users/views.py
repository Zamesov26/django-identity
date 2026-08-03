from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from users.identity.serializers import MeSerializer


class MeAPIView(APIView):
    """
    Возвращает информацию о текущем пользователе.
    """

    permission_classes = [
        IsAuthenticated,
    ]

    @extend_schema(
        tags=["Authentication"],
        summary="Current user",
        description="Возвращает информацию о текущем пользователе.",
        responses=MeSerializer,
    )
    def get(self, request):
        serializer = MeSerializer(
            request.user,
            context={
                "request": request,
            },
        )

        return Response(serializer.data)
