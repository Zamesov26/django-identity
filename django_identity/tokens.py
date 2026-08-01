from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class AuthTokens:
    access_token: str
    refresh_token: str | None
    expires_at: datetime