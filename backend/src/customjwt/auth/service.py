from fastapi import Request, Response
from customjwt.auth.transport.cookie import CookieTransport
from customjwt.auth.backend.jwt import JwtBackend


class AuthService:
    def __init__(
        self,
        backend: JwtBackend,
        transport: CookieTransport,
    ):
        self._backend = backend
        self._transport = transport

    def login(self, response: Response, sub: str, scope: list) -> None:
        access_token = self._backend.write_access_token(sub, scope)
        refresh_token = self._backend.write_refresh_token(sub)
        self._transport.login_response(
            response,
            access_token=access_token,
            refresh_token=refresh_token,
        )

    def logout(self, request: Request, response: Response) -> None:
        token = self._transport.from_request_access_token(request)
        if token:
            self._transport.logout_response(response)
        return None

    def refresh(self, request: Request, response: Response) -> None:
        refresh_token = self._transport.from_request_refresh_token(request)
        if not refresh_token:
            return

        is_valid = self._backend.validate_token(refresh_token)
        if not is_valid:
            return

        identity = self._backend.read_token(refresh_token)
        if identity:
            self.login(response, identity["sub"])


auth = AuthService(
    backend=JwtBackend(),
    transport=CookieTransport(),
)
