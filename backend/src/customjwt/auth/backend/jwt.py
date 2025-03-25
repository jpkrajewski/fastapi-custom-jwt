from datetime import datetime, timedelta, timezone
from uuid import uuid4
import jwt
from customjwt.config import config


class JwtBackend:
    def __init__(
        self,
        secret_key: str = config.secret_key,
        algorithm: str = config.algorithm,
        lifetime_seconds_access: int = config.lifetime_seconds_access,
        lifetime_seconds_refresh: int = config.lifetime_seconds_refresh,
        issuer: str = config.issuer,
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.lifetime_seconds_access = lifetime_seconds_access
        self.lifetime_seconds_refresh = lifetime_seconds_refresh
        self.issuer = issuer

    def write_access_token(self, sub: str, scope: list):
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
                "scope": scope,
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

    def read_token(self, token: str, /, raises: bool = False) -> dict:
        payload = self._decode(token)
        if not payload:
            if raises:
                raise ValueError("Invalid token")
            return {}
        return payload

    def validate_token(self, token: str) -> bool:
        return bool(self._decode(token))

    def _decode(self, token: str) -> dict | None:
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
        except (jwt.InvalidTokenError, jwt.ExpiredSignatureError):
            return None
