from typing import Annotated, Any
import secrets # Специальный модуль для проверки совпадений (паролей)
import uuid
import time

from fastapi import APIRouter, Depends, HTTPException, status, Header, Response, Cookie
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from api_auth.views_headers import get_username_by_static_auth_token

router = APIRouter(prefix="/auth", tags=["Cookie Auth 🍪"])




#Воспользуемся уже известным способом логина, через заголовки.

static_auth_token_to_username = {
    "c9624d38790eaba95545c3048597a949": "stap",
    "139c9bde43b1cfe4c1611bdef89659bf": "memo"
}

#Создадим временное хранилие наших кук о пользователях, которые выполнили вход
COOKIES: dict[str, dict][str, Any] = {}
COOKIE_SESSION_ID_KEY = "web-app-session-id"

def generate_session_id() -> str:
    return uuid.uuid4().hex

def get_session_data(
    session_id: str = Cookie(alias=COOKIE_SESSION_ID_KEY)
) -> dict:
    if session_id not in COOKIES:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="Invalid session id / not authenticated")
    
    return COOKIES[session_id]

@router.post("/login-cookie")
async def auth_login_set_cookie(
    response: Response,
    static_token: str = Depends(get_username_by_static_auth_token)
) -> str:
    #Если же проверка прошла, то нам нужно сохранить информацию, и отправить пользователю ответ, что мы запомнили его.
    # Ответ от сервера, когда пользовател успешно залогинился
    #Чтобы установить куку, нам нужен спецальный ключ, откуда мы эту куку и читаем

    session_id = generate_session_id()
    #Ставим куку
    response.set_cookie(COOKIE_SESSION_ID_KEY, session_id)
    #Сохраняем данную куку в нашу БД, в нее можно передать любые данные, которые нужны нам для работы с пользователем
    COOKIES[session_id] = {
        "username": static_token,
        "login_at": int(time.time())
    }

    return "set cookie: ok"

@router.get("/check_cookie")
async def auth_check_cookie(
    user_session_data: dict = Depends(get_session_data)
):
    username = user_session_data["username"]
    return {
        "message": f"Hello, {username}!",
        **user_session_data,
    }

@router.get("/logout_cookie")
async def auth_logout_cookie(
    response: Response,
    session_id: str = Cookie(alias=COOKIE_SESSION_ID_KEY),
    user_session_data: dict = Depends(get_session_data)
):
    #Отствим ту же проверку на логин, если мы не залогинены, то какой смысл разлогиниваться?)
    #Ну и получим тот-же session id из cookie, чтобы удалить ее
    #А в ответе, обязательно нужно сделать remove cookie!

    COOKIES.pop(session_id)
    #Удаляем в ответе id cookie
    response.delete_cookie(COOKIE_SESSION_ID_KEY)

    username = user_session_data["username"]
    return {
        "message": f"Bye, {username}!",
        **user_session_data,
    }
