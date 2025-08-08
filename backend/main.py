from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

app = FastAPI()

# API endpoint
@app.get("/api/hello")
async def hello():
    return {"message": "Hello from Python backend!"}

# Для разработки (если нужно обслуживать статику через Python)
app.mount("/static", StaticFiles(directory="../frontend"), name="static")
