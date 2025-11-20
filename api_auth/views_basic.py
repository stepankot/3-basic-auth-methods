from typing import Annotated
import secrets # Специальный модуль для проверки совпадений (паролей)

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

router = APIRouter(prefix="/auth", tags=["Basic Auth 🔓"])

#Базовая API для Basic Auth
#Basic Auth - простой вход по логину и паролю, который мы передаем прямо в адресной строке
#Либо браузер спросит нас эти данные
#(Передаются в заголовках)


#Credentials — учётные данные. Это информация, которая используется для проверки личности пользователя и обеспечения доступа только авторизованных пользователей к конфиденциальной информации и ресурсам.


# HTTPBasicCredentials - Pydantic модель, имеет поля username и password
# HTTPBasic - Вызывает метод __call__, который проверяте данные в заголовке request.headers.get("Authorization") - Проверка, выполнен ли вход.

security = HTTPBasic()

#При помощи security получить данные аунтефикации с помощью Depends


#Описали как будет работать наш view с basic_auth
#Осталось только передать данные для входа
#Неважно какой будет username и password
#Данных, достаточно, чтобы попасть в View


# Через адресную строку авторизоваться по данной api можно следующим образом:
# http://username:password@127.0.0.1:8000/auth/basic-auth

@router.get("/basic-auth")
async def basic_auth_credentials(credentials: Annotated[HTTPBasicCredentials, Depends(security)]):

    '''Аунтетификация пользователя по username и password\n
    Достаточно ввести имя, чтобы аунтетифицироваться'''

    return {"message": "hello!", 
            "username": credentials.username, 
            "password": credentials.password
        }

#Теперь научимся сравнивать пользователя по его имени.
#мы хотим предоставлять доступ тому пользователю, которого мы знаем

# Эмулируем данные с БД (Пароли конечно же должны быть "засолены")
usernames_to_passwords = [
    {"username": "stap", "password": "kotomen"},
    {"username": "john", "password": "memento10"}
]

def get_auth_user(
    credentials: Annotated[HTTPBasicCredentials, Depends(security)]
):
    #Создаем ошибку, которую выкенем в случае, если что-то из данных неправильно
    unauthed_exc = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
    detail="Invalid username or password",
    headers={"WWW-Authenticate": "Basic"})

    #Делаем проверку

    for user in usernames_to_passwords:

        #Если такое имя пользователя есть:
        #То проверить его пароль

        if credentials.username in user["username"]:
            if not secrets.compare_digest(
                credentials.password.encode("utf-8"), 
                user["password"].encode("utf-8")
            ):
                raise unauthed_exc
            return user #Возвращаем пользователя, который прошел проверку
        
    raise unauthed_exc #В противном случае - данные не корректны

@router.get("/basic-auth-user")
async def basic_auth_user(
    auth_user: object = Depends(get_auth_user)):
    '''Проверка прав доступа к данному endpoint пользователя по его login и password'''

    return {"message": f"Hi, {auth_user["username"]}",
            "user": auth_user}
