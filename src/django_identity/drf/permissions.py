from rest_framework.permissions import BasePermission


class IsIdentityAuthenticated(BasePermission):
    """Allows requests with any successfully verified identity."""

    def has_permission(self, request, view):
        return getattr(request, "identity", None) is not None


class IsHumanActor(BasePermission):
    """Allows human identities resolved to an authenticated Django user."""

    def has_permission(self, request, view):
        identity = getattr(request, "identity", None)
        actor = getattr(request, "actor", None)
        user = getattr(request, "user", None)

        return bool(
            identity is not None
            and actor is not None
            and actor.actor_type == "human"
            and user is not None
            and user.is_authenticated
        )


class IsSystemActor(BasePermission):
    """Allows system identities without requiring a Django user."""

    def has_permission(self, request, view):
        identity = getattr(request, "identity", None)
        actor = getattr(request, "actor", None)

        return bool(
            identity is not None
            and actor is not None
            and actor.actor_type == "system"
        )


class HasRequiredScopes(BasePermission):
    """Разрешить запрос при наличии всех scopes, требуемых представлением."""

    def has_permission(self, request, view):
        identity = getattr(request, "identity", None)
        required_scopes = getattr(view, "required_identity_scopes", None)

        if (
            identity is None
            or not isinstance(required_scopes, (list, tuple, set))
            or not all(isinstance(scope, str) for scope in required_scopes)
        ):
            return False

        return set(required_scopes).issubset(identity.scopes)
