from functools import wraps
from fastapi import HTTPException

def protected(f):
    @wraps(f)
    async def is_authenticated(*args,**kwargs):
        access_token = kwargs["access_token"]
        if access_token is None:
            raise HTTPException(status_code=401, detail="Not authenticated")
        return await f(*args,**kwargs)
    return is_authenticated
