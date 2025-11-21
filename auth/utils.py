import jwt
import bcrypt
from config import settings
from datetime import timedelta
from datetime import datetime

#Создадим функции-помощники, которые помогут парсить JWT токены
def encode_jwt(
    payload: dict, 
    alghoritm: str = settings.auth_jwt.algorithm,
    private_key: str = settings.auth_jwt.private_key_path.read_text(),  #Секретный ключ
    expire_timedelta: timedelta | None = None,
    expire_minutes: int = settings.auth_jwt.access_token_expire_minutes,
):
    #Добавим в пейлоад время жизни токена и время регистрации токена
    to_encode = payload.copy()
    now = datetime.utcnow()

    if expire_timedelta:
        expire = now + expire_timedelta
    else:
        expire = now + timedelta(minutes=expire_minutes)

    to_encode.update(exp=expire, iat=now)

    encoded = jwt.encode(to_encode, private_key, alghoritm) #Создаем токен
    return encoded

def decode_jwt(
    token: str | bytes,  
    public_key: str = settings.auth_jwt.public_key_path.read_text(),
    alghoritm: str = settings.auth_jwt.algorithm
    ):
    #Проверяем, что токен существует
    if token:
        try:
            decoded = jwt.decode(token, public_key, alghoritms=[alghoritm]) #Декодируем токен
            return decoded
        except jwt.DecodeError:
            return None
        

def hash_password(
    password: str,
) -> bytes:
    salt = bcrypt.gensalt()
    pwd_bytes: bytes = password.encode()
    return bcrypt.hashpw(pwd_bytes, salt)


def validate_password(
    password: str,
    hashed_password: bytes,
) -> bool:
    return bcrypt.checkpw(
        password=password.encode(),
        hashed_password=hashed_password,
    )