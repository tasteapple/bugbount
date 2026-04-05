# Bug Bounty Automation Framework (BBAF) - Architecture & Workflow

20년차 버그바운티 헌터의 노하우를 집약한 자동화 파이프라인 아키텍처입니다. 단순한 스캐너를 넘어, **정찰(Recon) -> 탐색(Discovery) -> 스캐닝(Scanning) -> 검증 및 익스플로잇(Exploitation) -> 리포팅(Reporting)** 까지 이어지는 End-to-End 프레임워크를 구축합니다.

---

## 1. 시스템 핵심 동작 워크플로우 (How it Works)

시스템은 비동기 분산 처리(예: Celery + Redis 또는 Go-routines)를 기반으로 하여 대규모 타겟을 빠르게 처리하도록 설계됩니다.

1. **Target Input (타겟 입력)**: 와일드카드 도메인(`*.example.com`), CIDR, 또는 특정 URL을 입력받습니다.
2. **Reconnaissance (초기 정찰)**: 서브도메인을 수집하고, 살아있는 IP와 포트를 식별하며, 동작 중인 웹 서비스를 찾습니다.
3. **Asset Profiling (자산 프로파일링)**: WAF 존재 여부, 사용 중인 기술 스택(CMS, 프레임워크, 서버 종류)을 파악하여 **맞춤형 공격 페이로드**를 준비합니다.
4. **Deep Discovery (심층 탐색)**: 숨겨진 파라미터, 과거 URL(Wayback Machine), 자바스크립트 파일 내 숨겨진 엔드포인트 및 API 키를 추출합니다.
5. **Vulnerability Scanning (취약점 스캐닝)**: 알려진 CVE, 설정 오류, 그리고 커스텀 페이로드를 주입하여 취약점을 찾습니다.
6. **Exploitation & Verification (자동 익스플로잇 및 검증)**: OOB(Out-of-Band) 서버를 활용한 Blind RCE/SSRF/SQLi 검증 및 실제 PoC(Proof of Concept) 코드를 실행하여 오탐(False Positive)을 제거합니다.
7. **Alert & Report (알림 및 리포트)**: 취약점이 확정되면 즉시 슬랙/디스코드/텔레그램으로 알림을 보내고, 제출용 Markdown/PDF 보고서를 생성합니다.

---

## 2. 모듈별 상세 검사 항목 (What to Check)

### Phase 1: Recon & Asset Discovery (정찰 및 자산 탐색)
* **Subdomain Enumeration**: Passive(OSINT, crt.sh) 및 Active(Bruteforce, Permutations) 방식을 결합하여 모든 서브도메인 확보.
* **Network Scanning**: Masscan/Naabu를 이용한 전 포트 스캔 및 Nmap을 통한 서비스 배너 그래빙.
* **Web Probing**: HTTP/HTTPS 응답 확인, 스크린샷 캡처(Gowitness/Aquatone)를 통한 시각적 분석.
* **Tech Stack Analysis**: Wappalyzer 패턴을 활용하여 구동 중인 기술(예: Spring, React, WordPress) 식별.

### Phase 2: Content Discovery & Crawling (콘텐츠 탐색 및 크롤링)
* **Directory & File Bruteforce**: Ffuf/Dirsearch를 이용한 백업 파일(`.bak`, `.zip`), 설정 파일(`.env`, `web.config`), 숨겨진 관리자 페이지 탐색.
* **Parameter Discovery**: Arjun/x8을 이용해 숨겨진 GET/POST 파라미터 발굴.
* **JS Analysis**: 자바스크립트 소스코드 내 하드코딩된 API 키, AWS Credentials, 내부 API 엔드포인트 추출.
* **History Analysis**: Waybackurls/Gau를 통해 현재는 링크되지 않은 과거의 취약한 엔드포인트 복원.

### Phase 3: Vulnerability Scanning (취약점 스캐닝)
* **CVE & Misconfiguration**: Nuclei 엔진을 활용한 최신 취약점 및 기본 설정 오류 스캔.
* **OWASP Top 10 집중 스캔**:
  * **SQL Injection**: Error-based, Time-based, Boolean-based 페이로드 자동 주입 및 검증.
  * **XSS**: Reflected, Stored, DOM 기반 XSS 페이로드 주입. 특히 WAF 우회 패턴 적용.
  * **SSRF (Server-Side Request Forgery)**: 내부망 IP(`169.254.169.254`, `127.0.0.1`) 및 클라우드 메타데이터 접근 시도.
  * **LFI / RFI**: `/etc/passwd` 또는 `c:/windows/win.ini` 등 로컬 파일 읽기 시도.
  * **CORS Misconfiguration**: 임의의 Origin을 허용하여 민감 정보를 탈취할 수 있는지 검증.
  * **Auth Bypass / IDOR**: 권한 우회 및 다른 유저의 객체 참조 가능 여부 테스트.

### Phase 4: Exploitation & PoC Generation (익스플로잇 및 PoC 생성)
*이 단계는 단순 스캔을 넘어 "진짜"를 증명하는 핵심입니다.*
* **OOB (Out-of-Band) Verification**: Interactsh 서버를 연동하여 Blind SSRF, Blind RCE, Log4j 등의 Pingback 응답을 캡처하여 오탐 제로화.
* **Auto-Exploit Scripts**: SQLMap API 연동으로 DB 탈취 증명, 취약한 업로드 폼에 Web Shell(무해한 PoC 형태) 업로드 후 코드 실행 증명.
* **Chaining Vulnerabilities**: XSS를 통해 관리자 세션을 탈취하고, 탈취한 세션으로 관리자 페이지의 파일 업로드 취약점을 트리거하여 RCE로 이어지는 시나리오 자동화.

---

## 3. 기술 스택 제안 (Tech Stack)
* **Core Language**: `Python 3` (비동기 처리를 위한 `asyncio`, API 통합의 용이성) 또는 `Go` (빠른 네트워크 I/O 속도). *추천: Python을 메인 오케스트레이터로 사용하고, 무거운 스캐닝 모듈은 Go로 작성된 오픈소스(Subfinder, Nuclei 등)를 서브프로세스로 래핑.*
* **Database**: `PostgreSQL` (수백만 개의 자산 데이터와 히스토리 관리) + `Redis` (작업 큐 및 캐싱).
* **Task Queue**: `Celery` (장기 실행 스캔 작업의 분산 처리).
* **UI / Dashboard**: `Vue.js` 또는 `React` 기반의 심플한 대시보드 (발견된 자산 및 취약점 시각화).

---

## 4. 다음 단계 (Next Steps)
1. **GitHub Repository 초기화**: 로컬에 Git을 세팅하고 구조를 잡습니다.
2. **Core 엔진 구성**: 입력받은 도메인을 파싱하고 비동기 워커에 던져주는 뼈대 코드를 작성합니다.
3. **Recon 모듈 구현**: 서브도메인 수집부터 시작하여 차근차근 모듈을 붙여나갑니다.
