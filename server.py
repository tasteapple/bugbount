from fastapi import FastAPI, Request
from fastapi.responses import HTML_Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
import json
import glob

app = FastAPI()

# 데이터 및 템플릿 경로 설정
RESULT_DIR = "data/results"
templates = Jinja2Templates(directory="web/templates")

@app.get("/", response_class=HTML_Response)
async def index(request: Request):
    # 저장된 리포트 목록 가져오기
    reports = glob.glob(f"{RESULT_DIR}/*.json")
    reports.sort(key=os.path.getmtime, reverse=True)
    
    latest_data = {}
    if reports:
        with open(reports[0], "r", encoding="utf-8") as f:
            latest_data = json.load(f)
            
    return templates.Template_Response("dashboard.html", {
        "request": request, 
        "reports": reports,
        "latest": latest_data
    })

@app.get("/api/stats")
async def get_stats():
    """최근 스캔 통계 API"""
    reports = glob.glob(f"{RESULT_DIR}/*.json")
    if not reports: return {"error": "No data"}
    
    with open(reports[0], "r", encoding="utf-8") as f:
        data = json.load(f)
    return data

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
