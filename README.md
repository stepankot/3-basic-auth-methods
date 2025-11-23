# Аунтефикация в FastAPI
Реализация всех методов аутентификации при помощи FastAPI
<img width="1634" height="881" alt="image" src="https://github.com/user-attachments/assets/074df26e-518f-4ca9-8764-4cd89ccae4a9" />

## Basic Auth
Базовая аутентификация
- Достаточно ввести только логин и пароль, чтобы получить доступ к endpoint
- Проверка аутентифицированного пользователя по его логину и паролю

<img width="1625" height="172" alt="image" src="https://github.com/user-attachments/assets/59b1f6d6-2a23-4102-a697-6d8a450cfd76" />


## Header Auth
Аунтетификация через зоголовки
<img width="1617" height="774" alt="image" src="https://github.com/user-attachments/assets/66a3f420-94f0-4323-859f-d9bb110b8905" />

## Cookie Auth
Через cookie
- Выдача cookie
- Чтение cookie
- Удаление cookie

<img width="1620" height="242" alt="image" src="https://github.com/user-attachments/assets/2e99adef-9479-47ec-a1a0-587718bc0e5f" />

## JWT token Auth
С помощью JWT токенов
- Выдача `access` токена и `refresh` токена
- Чтение `access` и `refresh` токенов
- Обновление истекшего `access` токена по `refresh` токену
- Хранение `access` и `refresh` токена в cookie

<img width="1614" height="302" alt="image" src="https://github.com/user-attachments/assets/f0285305-509d-4a58-ab6b-64aa4683633a" />
