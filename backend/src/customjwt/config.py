from pydantic import Field
from pydantic_settings import BaseSettings


class Config(BaseSettings):
    secret_key: str = Field(default="secret")
    algorithm: str = Field(default="HS256")
    lifetime_seconds_access: int = Field(default=60)
    lifetime_seconds_refresh: int = Field(default=300)
    issuer: str = Field(default="customjwt")
    jwt_access_cookie_name: str = Field(default="access_token")
    jwt_refresh_cookie_name: str = Field(default="access_token")
    jwt_access_cookie_max_age: int = Field(default=60 * 30)
    jwt_refresh_cookie_max_age: int = Field(default=60 * 60 * 24 * 14)


config = Config()
