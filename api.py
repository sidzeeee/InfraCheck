# api.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from engine import run_infracheck

app = FastAPI(title="InfraCheck API")

# Allow frontend to talk to backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# This defines what the frontend sends us
class CodeInput(BaseModel):
    code: str
    region: str = "eastus"


@app.get("/")
def root():
    return {"status": "InfraCheck API is running"}


@app.post("/analyze")
def analyze(input: CodeInput):
    """
    Main endpoint.
    Frontend sends Bicep code.
    We return the full analysis.
    """
    
    try:
        result = run_infracheck(input.code)
        
        if not result:
            return {
                "success": False,
                "error": "No resources found in code"
            }
        
        return {
            "success": True,
            "resources": result['resources'],
            "security_issues": result['security_issues'],
            "cost": result['cost'],
            "verdict": result['verdict']
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@app.get("/health")
def health():
    return {"status": "healthy"}