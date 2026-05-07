from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import settings
from routers import auth_router, alerts_router, pipeline_router
from routers.ml_router import router as ml_router, load_ml_models
from routers.splunk_router import router as splunk_router

app = FastAPI(
    title="RAID-SecOps API",
    version="0.4.0",
    description="Role-Aware AI Decision Support — Backend API",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(alerts_router.router)
app.include_router(pipeline_router.router)
app.include_router(ml_router)
app.include_router(splunk_router)

@app.on_event("startup")
async def startup():
    print("[STARTUP] Loading ML model artifacts...")
    success = load_ml_models()
    if success:
        print("[STARTUP] ML models ready.")
    else:
        print("[STARTUP] ⚠ ML models not loaded — check ML_MODEL_DIR in .env")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "RAID-SecOps API", "version": "0.4.0"}