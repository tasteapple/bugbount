# BBAF: Bug Bounty Automation Framework

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

20년 경력의 버그바운티 헌터 노하우가 집약된 자동화 취약점 탐색 및 익스플로잇 프레임워크입니다.

## 🚀 주요 기능 (Features)
- **Recon (정찰)**: 서브도메인 수집, 포트 스캐닝, 서비스 식별
- **Discovery (탐색)**: 숨겨진 파라미터, 과거 URL, JS 코드 분석
- **Scanning (스캐닝)**: Nuclei 엔진 연동 및 커스텀 취약점 스캔 (OWASP Top 10)
- **Exploitation (익스플로잇)**: OOB(Interactsh) 기반 검증 및 자동화된 PoC 실행
- **Reporting (리포팅)**: 실시간 알림 (Slack/Discord) 및 리포트 생성

## 🛠️ 기술 스택 (Tech Stack)
- **Core**: Python 3 (Asyncio)
- **Engine Wrappers**: Go-based tools (Subfinder, Nuclei, Naabu)
- **Database**: PostgreSQL / Redis (Task Queue)
- **Verification**: Interactsh (OOB)

## 📦 설치 및 시작하기 (Getting Started)
*상세 설치 가이드는 준비 중입니다.*

```bash
git clone https://github.com/tasteapple/bugbount.git
cd bugbount
pip install -r requirements.txt
python main.py --target example.com
```

## ⚠️ Disclaimer
본 도구는 보안 진단 및 교육 목적으로만 사용해야 합니다. 허가받지 않은 대상에 대한 공격은 법적 처벌을 받을 수 있습니다.
