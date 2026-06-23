from contextlib import asynccontextmanager

from fastapi import FastAPI

from server.database import init_db
from server.models import HealthResponse


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="E2EE Relay Server", version="0.1.0", lifespan=lifespan)


@app.get("/health", response_model=HealthResponse)
def health():
    return {"status": "ok"}
