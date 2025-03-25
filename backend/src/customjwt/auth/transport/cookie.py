from typing import Literal, Optional
from fastapi import Response, Request
from customjwt.config import config


class CookieTransport:
    def __init__(
        self,
        name_jwt_access: str = config.jwt_access_cookie_name,
        name_jwt_refresh: str = config.jwt_refresh_cookie_name,
        max_age_access: int = config.jwt_access_cookie_max_age,
        max_age_refresh: int = config.jwt_refresh_cookie_max_age,
        path: str = "/",
        domain: str | None = None,
        secure: bool = True,
        httponly: bool = True,
        samesite: Literal["lax", "strict", "none"] = "lax",
    ):
        self._name_jwt_access = name_jwt_access
        self._name_jwt_refresh = name_jwt_refresh
        self._max_age_access = max_age_access
        self._max_age_refresh = max_age_refresh
        self._path = path
        self._domain = domain
        self._secure = secure
        self._httponly = httponly
        self._samesite = samesite

    def from_request_access_token(self, request: Request) -> str | None:
        return request.cookies.get(self._name_jwt_access)

    def from_request_refresh_token(self, request: Request) -> str | None:
        return request.cookies.get(self._name_jwt_refresh)

    def login_response(
        self, response: Response, access_token: str, refresh_token: str
    ) -> None:
        self.set_cookie(
            response, self._name_jwt_access, access_token, self._max_age_access
        )
        self.set_cookie(
            response, self._name_jwt_refresh, refresh_token, self._max_age_refresh
        )

    def logout_response(self, response: Response) -> None:
        response.delete_cookie(self._name_jwt_access)
        response.delete_cookie(self._name_jwt_refresh)

    def set_cookie(
        self, response: Response, token_name: str, token_value: str, max_age: int
    ) -> None:
        response.set_cookie(
            token_name,
            token_value,
            max_age=max_age,
            path=self._path,
            domain=self._domain,
            secure=self._secure,
            httponly=self._httponly,
            samesite=self._samesite,
        )
