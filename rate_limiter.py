from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from collections import defaultdict
import time

class RateLimiterMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, endpoint_limits: dict):
        super().__init__(app)
        self.endpoint_limits = endpoint_limits
        self.requests = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        current_time = time.time()
        path = request.url.path

        limit, period = self.endpoint_limits.get(path, (None, None))
        if limit is None:
            return await call_next(request)

        if client_ip not in self.requests:
            self.requests[client_ip] = [current_time]
        else:
            self.requests[client_ip] = [timestamp for timestamp in self.requests[client_ip] if current_time - timestamp < period]
            self.requests[client_ip].append(current_time)

        if len(self.requests[client_ip]) > limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        response = await call_next(request)
        return response
