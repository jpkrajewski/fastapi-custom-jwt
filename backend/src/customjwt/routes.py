from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from customjwt.auth.service import auth
from customjwt.permissions import JWTAccessCookie, JWTAdminCookie, JWTRefreshCookie
from customjwt.models import TokenRequest

router = APIRouter()


@router.post("/token", status_code=200)
async def token(login_request: TokenRequest, response: Response):
    try:
        if login_request.username == "user" and login_request.password == "password":
            auth.login(response, sub="user", scope=["user", "admin"])
            response.status_code = 200
            return {"message": "Logged in"}
        else:
            raise HTTPException(status_code=401, detail="Unauthorized")
    except:
        raise HTTPException(status_code=401, detail="Unauthorized")


@router.post("/logout", dependencies=[Depends(JWTAccessCookie())])
async def logout(response: Response, request: Request):
    try:
        auth.logout(request, response)
        return response
    except:
        raise HTTPException(status_code=401, detail="Unauthorized")


@router.post("/refresh", dependencies=[Depends(JWTRefreshCookie())])
async def refresh(response: Response, request: Request):
    try:
        auth.refresh(request, response)
        response.status_code = 200
        return {"message": "Token refreshed"}
    except:
        raise HTTPException(status_code=401, detail="Unauthorized")


@router.get("/protected", dependencies=[Depends(JWTAccessCookie())])
async def protected(request: Request):
    return {"secret": "My super secret information"}


@router.get("/only-admin", dependencies=[Depends(JWTAdminCookie())])
async def only_admin(request: Request):
    return {"secret": "My super secret information for admins"}
