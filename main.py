from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes.api import auth_router
import uvicorn

# Create the FastAPI app
app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]  # Add this to expose all headers
)
app.include_router(auth_router)
# Example route
@app.get("/")
def read_root():
    return {"message": "Hello, world!"}

if __name__ == "__main__":
    uvicorn.run(app, port=8000)