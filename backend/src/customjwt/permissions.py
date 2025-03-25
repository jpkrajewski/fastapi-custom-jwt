from customjwt.config import config
from fastapi.security import APIKeyCookie
from fastapi import Request
from customjwt.auth.backend.jwt import JwtBackend


class MissingJWTCookieException(Exception):
    code = 401
    error_code = "JWT_COOKIE__MISSING"
    message = "missing jwt cookie"


class InvalidJWTCookieException(Exception):
    code = 401
    error_code = "JWT_COOKIE__INVALID"
    message = "invalid jwt cookie"


class JWTCookie(APIKeyCookie):
    async def __call__(self, request: Request):
        cookie: str | None = request.cookies.get(self.model.name)
        if not cookie:
            raise MissingJWTCookieException
        if not JwtBackend().validate_token(cookie):
            raise InvalidJWTCookieException
        try:
            if not self.check_additional_fields(
                JwtBackend().read_token(cookie, raises=True)
            ):
                raise InvalidJWTCookieException
        except ValueError:
            raise InvalidJWTCookieException
        return cookie

    def check_additional_fields(self, payload: dict) -> bool:
        return True


class JWTAccessCookie(JWTCookie):
    def __init__(
        self,
        name: str = config.jwt_access_cookie_name,
        scheme_name: str = "JWTAccessCookie",
        description: str = "JWT access cookie - used for authentication.",
        auto_error: bool = True,
    ):
        super().__init__(
            name=name,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )


class JWTRefreshCookie(JWTCookie):
    def __init__(
        self,
        name: str = config.jwt_refresh_cookie_name,
        scheme_name: str = "JWTRefreshCookie",
        description: str = "JWT refresh cookie - used for refreshing access token.",
        auto_error: bool = True,
    ):
        super().__init__(
            name=name,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )


class JWTAdminCookie(JWTAccessCookie):
    def check_additional_fields(self, payload: dict) -> bool:
        return "admin" in payload.get("scope", [])
