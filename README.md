# BBAF: Bug Bounty Automation Framework (END-GAME Build) 🚀

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Build](https://img.shields.io/badge/Build-God--Tier-magenta.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

20년 경력의 버그바운티 헌터 노하우가 집약된 **최종 진화형 자동화 취약점 탐색 및 익스플로잇 프레임워크**입니다. 단순한 패턴 매칭을 넘어 비즈니스 로직, 클라우드 인프라, 그리고 내부망 침투(Pivoting)까지 자동화합니다.

## 🌟 핵심 고도화 기능 (Elite Features)

### 1. 전방위 자산 정찰 (Master Recon)
- **Asset Correlation**: SSL 인증서(SAN) 파싱 및 Favicon Hashing을 통한 Shadow IT 자산 발굴.
- **Deep Permutations**: 수집된 서브도메인을 기반으로 수천 개의 변조 조합을 생성하여 숨겨진 스테이징/개발 서버 탐지.

### 2. 신의 영역 공격 (God-Tier Exploitation)
- **Race Condition (Turbo Burst)**: 동시성 제어 미흡을 이용한 포인트/쿠폰 중복 사용 및 로직 우회.
- **HTTP Request Smuggling**: 프론트엔드-백엔드 간 프로토콜 해석 차이를 이용한 요청 하이재킹.
- **SSRF to Internal Pivoting**: SSRF 취약점을 징검다리 삼아 내부망의 Redis, Docker, Jenkins 등을 직접 타격하여 RCE 연계.

### 3. 현대적 웹 취약점 (Modern Web Attacks)
- **Cloud & K8s Security**: AWS/GCP/Azure 메타데이터 API 탈취 및 Kubernetes Secrets 노출 진단.
- **Advanced Injection**: SSTI(Template Injection), Blind NoSQLi, Prototype Pollution 자동 탐지.
- **Auth & Logic**: OAuth Redirect Hijacking, JWT alg:none 분석, 403 Forbidden Bypass (20+ 기법).

### 4. 클라이언트 사이드 보안 (Browser Level)
- **postMessage Analyzer**: Window 간 통신 시 Origin 검증 미흡을 통한 데이터 탈취 분석.
- **CSWSH**: Cross-Site WebSocket Hijacking 가능성 진단.

## 🛠️ 기술 스택 (Tech Stack)
- **Core**: Python 3.12+ (Asyncio & ThreadPoolExecutor)
- **Analysis**: Regex-based JS Secrets Extraction, Differential Response Analysis
- **Reporting**: Auto-generated Markdown Reports & Real-time Alerting

## 📦 시작하기 (Quick Start)

```bash
# 레포지토리 클론
git clone https://github.com/tasteapple/bugbount.git
cd bugbount

# 의존성 설치
pip install -r requirements.txt

# 마스터 레벨 스캔 시작
python main.py -t example.com
```

## 📂 프로젝트 구조 (Structure)
- `core/`: 프레임워크 핵심 엔진
- `modules/`: 20여 개의 전문화된 취약점 탐지/익스플로잇 모듈
- `data/results/`: 스캔 결과 및 마크다운 리포트 저장소
- `config/`: 스캔 설정 및 API 키 관리

## ⚠️ Disclaimer
본 도구는 보안 진단 및 교육 목적으로만 사용해야 합니다. 허가받지 않은 대상에 대한 공격은 법적 처벌을 받을 수 있으며, 모든 책임은 사용자에게 있습니다.

---
**Distilled with 20 Years of Experience by a Veteran Hunter.**
