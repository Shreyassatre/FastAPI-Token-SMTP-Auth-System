from fastapi import FastAPI
from .rate_limiter import RateLimiterMiddleware
from .routes import auth, user, admin
from fastapi.staticfiles import StaticFiles

from .database import engine, Base

Base.metadata.create_all(bind=engine)

description = """
### Note:
#### To operate as admin use below credentials as only admin can set another admin from registered users.
- `username`: admin
- `password`: admin

for demonstration purpose admin's 2 factor authentication is disabled.

#### Two-Factor Authentication (2FA)

- By default, 2 Factor Authentication is enabled for all users.
- Users/admins must verify the OTP sent to their email to access secure endpoints.

- Users/admins can disable two-factor authentication via their profile update.

#### Rate Limiter

##### Endpoints with Rate Limiting:
- `/login`: 5 requests per minute
- `/register`: 5 requests per minute
- `/password-reset-request/`: 5 requests per minute
- `/verify-email/`: 5 requests per minute
- `/reset-password/`: 5 requests per minute

"""

app = FastAPI(description=description,)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(auth.router)
app.include_router(user.router)
app.include_router(admin.router)

endpoint_limits = {
    "/login": (5, 60), 
    "/register/": (5, 60),
    "/password-reset-request/":(5, 60),
    "/verify-email/":(5,60),
    "/reset-password":(5,60)
}

app.add_middleware(RateLimiterMiddleware, endpoint_limits=endpoint_limits)








