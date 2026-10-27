from django.contrib.auth import get_user_model

from django_identity.identity.identity import Identity
from django_identity.identity.user_resolver import UserResolver

User = get_user_model()


class DjangoUserResolver(UserResolver):
    def resolve(
        self,
        identity: Identity,
    ) -> User | None:

        if identity.actor.actor_type != "human":
            return None

        return User.objects.filter(
            pk=identity.actor.subject,
        ).first()
