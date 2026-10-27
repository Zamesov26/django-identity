from rest_framework.authentication import BaseAuthentication


class IdentityAuthentication(BaseAuthentication):

    def authenticate(self, request):
        identity = getattr(request._request, "identity", None)

        if identity is None:
            return None

        return (
            request._request.user,
            identity,
        )
