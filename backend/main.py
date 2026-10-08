import os
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from api.routes import router as api_router

app = FastAPI(
    title="AI-Powered Phishing Website Detector API",
    description="Multi-perspective website cybersecurity analysis engine combining Machine Learning, URL structure, HTML inspection, NLP, Domain WHOIS, SSL validation, and Brand Detection.",
    version="1.0.0"
)

# Enable CORS for frontend web client
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
