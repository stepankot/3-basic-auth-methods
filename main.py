from fastapi import FastAPI
from api_auth.views_basic import router as basic_auth_router
from api_auth.views_headers import router as header_auth_router
from api_auth.views_cookie import router as cookie_auth_router

app = FastAPI()

app.include_router(router=basic_auth_router)
app.include_router(router=header_auth_router)
app.include_router(router=cookie_auth_router)
