import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    person_uid_1c_erp = models.UUIDField(
        unique=True,
        default=uuid.uuid4,
        db_index=True,
    )
