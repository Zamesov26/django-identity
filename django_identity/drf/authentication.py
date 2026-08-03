from rest_framework.authentication import BaseAuthentication


class IdentityAuthentication(BaseAuthentication):

    def authenticate(self, request):
        user = request._request.user

        if not user.is_authenticated:
            return None

        return (
            user,
            request._request.identity,
        )