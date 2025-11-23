from typing import Annotated
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from datetime import timedelta

from pydantic import BaseModel
from schemas.user import UserSchema


from fastapi import APIRouter, Depends, HTTPException, status, Cookie, Form, Response, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import auth.utils as utils
from config import settings

#Реализуем выпуск и проверку токена через cookie
#pyjwt[crypto]
#Реализуем хеш пароля
#Нужно сгенирировать public key и private key

#Создаем Тестовые данные
stap = UserSchema(username="stap", 
                  password=utils.hash_password("eshkaAbshka12"),
                  email="stepakot0@gmail.com")

viola = UserSchema(username="viola", 
                  password=utils.hash_password("violech2k1a"),
                  email="viola@gmail.com")

#регестрируем данные в тестовую БД
user_db: dict[str, UserSchema] = {
    stap.username: stap,
    viola.username: viola
}

#Теперь реализуем то, зачем мы собрались, сделаем выпуск токена, если пользователь ввел правильные данные.
router = APIRouter(prefix="/auth", tags=["Access Token 🔑"])

#Будем класть токен в Cookie
#Напишем функцию для проверки пользователя по форме
#python-multipart

def validate_user(username: str = Form(), password: str = Form()):
    unauthed_exc = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
    detail="Invalid username or password",
    headers={"WWW-Authenticate": "Basic"})

    if not (user := user_db.get(username)):
        raise unauthed_exc
    
    if not utils.validate_password(
        password, 
        hashed_password=user.password):

        raise unauthed_exc

    return user

#Создадим pydantic схему, по которой будем выдавать наш токен

class TokenInfo(BaseModel):
    acces_token: str
    refresh_token: str #Добавляем refresh токен
    token_type: str = "bearer"

COOKIE_SESSION_ID_KEY = "web-app-jwt-id"
COOKIE_REFRESH_TOKEN_KEY = "web-app-jwt-refresh-id"

TOKEN_TYPE_FIELD = "type"
ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"

def create_jwt(token_type: str, token_data: dict, 
               expire_minutes: int = settings.auth_jwt.access_token_expire_minutes,
               expire_timedelta: timedelta | None = None ) -> str:
    #Нам нужно различать типы токена, refresh и access
    #Для этого укажем в payload тип токена
    jwt_payload = {TOKEN_TYPE_FIELD: token_type}
    jwt_payload.update(token_data)
    return utils.encode_jwt(
        payload=jwt_payload,
        expire_minutes=expire_minutes,
        expire_timedelta=expire_timedelta
        )

#Создадим функцию для выпуска access токена
def create_access_token(user: UserSchema):
    if user:
        jwt_payload = {"username": user.username,
                       "email": user.email}
        
        return create_jwt(ACCESS_TOKEN_TYPE, 
        jwt_payload, 
        expire_minutes=settings.auth_jwt.access_token_expire_minutes
        )
    
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

def create_refresh_token(user: UserSchema):
    if user:
        jwt_payload = {"sub": user.username} #refresh токен нужен только для того, чтобы обновлять access токен
        
        return create_jwt(REFRESH_TOKEN_TYPE, 
            jwt_payload, 
            expire_timedelta=timedelta(days = settings.auth_jwt.refresh_token_expire_days)
        )
    
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

@router.post("/login", response_model=TokenInfo)
async def auth_user_issue_jwt(response: Response, user: UserSchema = Depends(validate_user)):
    #Переиспользуем нашу новую функцию для создания acces токена
    #Создаем функцию, которая выпускает refresh токен
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)

    response.set_cookie(COOKIE_SESSION_ID_KEY, value=access_token)
    response.set_cookie(COOKIE_REFRESH_TOKEN_KEY, value=refresh_token)

    return TokenInfo(acces_token=access_token, refresh_token=refresh_token)

@router.get("/users_token")
async def ckeck_user_issue_jwt(acess_token: str = Cookie(alias=COOKIE_SESSION_ID_KEY)):

    """Возвращаем декодированный payload токена, взятого из cookie"""

    payload = utils.decode_jwt(token=acess_token)
    
    if payload:
        return payload
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
                            detail="Invalid username or password",
                            headers={"WWW-Authenticate": "Basic"})
    
def get_current_auth_user_for_refresh(refresh: str = Cookie(alias=COOKIE_REFRESH_TOKEN_KEY)):

    if not refresh:
        raise HTTPException(status_code=401, detail="Refresh token is missing")
    
    try: 
        refresh_payload = utils.decode_jwt(refresh)
        if refresh_payload:
            username = refresh_payload.get("sub")
            user = user_db.get(username)
            if not user:
                raise HTTPException(status_code=401, detail="user not found")
            return user
        raise HTTPException(status_code=401, detail="user payload no found")
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired, please login")

@router.post("/refresh_token")
async def refresh_token(response: Response, user: UserSchema = Depends(get_current_auth_user_for_refresh)):
    
    new_access = create_access_token(user)
    response.set_cookie(COOKIE_SESSION_ID_KEY, value =new_access)
    return new_access


#Забираем токен из cookie
def get_payload_user_token(token: str = Cookie(alias=COOKIE_SESSION_ID_KEY)):
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is missing",
        )

    try:
        payload = utils.decode_jwt(token=token)
        token_type = payload.get(TOKEN_TYPE_FIELD)
        if token_type != ACCESS_TOKEN_TYPE:
            raise HTTPException(status_code=401, detail=f"Invalid token type {token_type!r} when expected {ACCESS_TOKEN_TYPE}")
        return payload
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired, (try to refresh)")

def get_current_auth_user(payload: dict = Depends(get_payload_user_token)):
    if payload:
        username = payload.get("username")
        user = user_db.get(username)
        return user
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token not found missing")


@router.get("/users/me")
async def auth_user_check_self_info(user: UserSchema = Depends(get_current_auth_user)):
    return {
        "user": user.username,
        "email": user.email
    }