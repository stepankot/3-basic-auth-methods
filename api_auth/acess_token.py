from typing import Annotated
import secrets # Специальный модуль для проверки совпадений (паролей)

from pydantic import BaseModel
from schemas.user import UserSchema


from fastapi import APIRouter, Depends, HTTPException, status, Cookie, Form
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
        password=password, 
        hashed_password=user.password):

        raise unauthed_exc

    return user

#Создадим pydantic схему, по которой будем выдавать наш токен

class TokenInfo(BaseModel):
    acces_token: str
    token_type: str

@router.post("/login", response_model=TokenInfo)
async def auth_user_issue_jwt(user: UserSchema = Depends(validate_user)):
    jwt_payload = {"usename": user.username, 
                   "email": user.email}
    
    access_token = utils.encode_jwt(payload=jwt_payload)

    return TokenInfo(acces_token=access_token, token_type="bearer")