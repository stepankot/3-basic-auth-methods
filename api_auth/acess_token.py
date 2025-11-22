from typing import Annotated
import secrets # Специальный модуль для проверки совпадений (паролей)
import jwt

from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from pydantic import BaseModel
from schemas.user import UserSchema


from fastapi import APIRouter, Depends, HTTPException, status, Cookie, Form, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import auth.utils as utils

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
    token_type: str

COOKIE_SESSION_ID_KEY = "web-app-jwt-id"

@router.post("/login")
async def auth_user_issue_jwt(response: Response, user: UserSchema = Depends(validate_user)):
    jwt_payload = {"username": user.username, 
                   "email": user.email}
    
    access_token = utils.encode_jwt(payload=jwt_payload)

    response.set_cookie(COOKIE_SESSION_ID_KEY, value=access_token)

    return {"message":"loggin in! Cookie was setted!"}

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
    

#Забираем токен из cookie
def get_payload_user_token(token: str = Cookie(alias=COOKIE_SESSION_ID_KEY)):
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is missing",
        )

    try:
        payload = utils.decode_jwt(token=token)
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