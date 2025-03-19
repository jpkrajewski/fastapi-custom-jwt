from datetime import datetime, timedelta, timezone
from math import e
from uuid import uuid4
import jwt


class JwtBackend:
    def __init__(
        self,
        secret_key: str,
        algorithm: str,
        lifetime_seconds_access: int,
        lifetime_seconds_refresh: int,
        issuer: str,
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.lifetime_seconds_access = lifetime_seconds_access
        self.lifetime_seconds_refresh = lifetime_seconds_refresh
        self.issuer = issuer

    def write_access_token(self, sub: str):
        iat = datetime.now(tz=timezone.utc)
        exp = iat + timedelta(seconds=self.lifetime_seconds_access)
        jti = str(uuid4())
        token = jwt.encode(
            payload={
                "sub": sub,
                "iss": self.issuer,
                "exp": exp,
                "iat": iat,
                "jti": jti,
            },
            key=self.secret_key,
            algorithm=self.algorithm,
        )
        return token

    def write_refresh_token(self, sub: str):
        iat = datetime.now(tz=timezone.utc)
        exp = iat + timedelta(seconds=self.lifetime_seconds_refresh)
        token = jwt.encode(
            payload={
                "sub": sub,
                "iss": self.issuer,
                "exp": exp,
                "iat": iat,
            },
            key=self.secret_key,
            algorithm=self.algorithm,
        )
        return token

    def read_token(self, token: str) -> dict:
        return self._decode(token)

    def validate_token(self, token: str) -> bool:
        return bool(self._decode(token))

    def _decode(self, token: str) -> dict:
        try:
            decoded = jwt.decode(
                token,
                self.secret_key,
                self.algorithm,
                options={
                    "verify_exp": True,
                    "verify_iss": True,
                    "verify_iat": True,
                    "verify_jti": True,
                },
            )
            return decoded
        except jwt.InvalidTokenError:
            return {}
