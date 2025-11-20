from typing import Annotated
import secrets # Специальный модуль для проверки совпадений (паролей)

from fastapi import APIRouter, Depends, HTTPException, status, Header
from fastapi.security import HTTPBasic, HTTPBasicCredentials

router = APIRouter(prefix="/auth", tags=["Header Auth ⤴️"])

#Сейчас мы не будем работать с заголовком Authorization, 
#Мы поработаем с любым заголовком, чтобы можно было посмотреть, что можно работать с любым заголовком #для аутентификации.


#Реализуем функцию-помощник, которая будет доставать информацию из заголовков
#И возвращать в username, username пользователя если тот аутентифицирован

static_auth_token_to_username = {
    "c9624d38790eaba95545c3048597a949": "stap",
    "139c9bde43b1cfe4c1611bdef89659bf": "memo"
}

def get_username_by_static_auth_token(
        static_token: str = Header(alias="x-auth-token")
) -> str:
    #Если не нашли токен
    if static_token not in static_auth_token_to_username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="Invalid token")

    #Если найден, то возвращаем имя пользователя по этому токену
    return static_auth_token_to_username[static_token]



@router.get("/some-http-header-auth")
async def auth_some_http_header(username: str = Depends(get_username_by_static_auth_token)):
    return {"message": f"Hi! {username}",
            "user": {username}}
