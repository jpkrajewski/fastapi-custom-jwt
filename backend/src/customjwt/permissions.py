from fastapi.security import APIKeyCookie
from fastapi import Request


class JWTAccessCookie(APIKeyCookie):
    pass


class JWTRefreshCookie(APIKeyCookie):
    pass
