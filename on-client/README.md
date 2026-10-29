# 내 보안 Agent 시작 틀 0.2.21

이 보안 Agent는 회사 직원이 자기 로그인 상태, 업무 앱 접속 결과, 최근 접속 기록과 보안 경보를 보는 보안 앱입니다. 13단계부터 22단계까지 이 프로젝트 하나로 화면을 채워 가며 완성합니다. 처음이라면 docs/GETTING_STARTED_STUDENT.md부터 읽습니다. 무엇을 왜 만드는지와 단계별 순서가 그 문서에 있습니다.

이 시작 틀을 받은 것만으로 단계를 통과하지 않습니다. 단계마다 docs/STUDENT_PROMPTS.md의 안내를 수업용 AI에 붙여 넣어 student/extension.mjs를 고치고, 화면에서 확인하고, 커밋한 뒤 ALEPH에 제출합니다. 제출하면 서버가 그 커밋의 코드를 받아 AI가 단계 과제 기준으로 읽고 판정합니다. 코드를 실행해서 판정하지 않습니다.

## 켜기

검수 환경은 Node.js 24.19.0이며 외부 npm 의존성이 없습니다. 이 폴더의 PowerShell에서 아래를 실행하고 PC 브라우저로 http://127.0.0.1:5189 를 엽니다. 자세한 켜기·끄기·다시 켜기는 docs/STUDENT_LAUNCH_GUIDE.md에 있습니다.

    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1

npm start도 같은 서버를 켭니다. 기본 실행은 실제 회사 시스템(기존 엔진)에 연결되지 않은 상태입니다. npm run demo는 예제 자료로 화면을 보여 줄 뿐이며 실제 연결이나 성취가 아닙니다. npm run check는 student/extension.mjs의 문법만 확인합니다.

## 지킬 것

- 기존 1~3차 프로젝트와 학생 파일은 지우거나 덮어쓰지 않습니다. 새 폴더에서 시작하거나, 이미 하던 프로젝트를 이어 씁니다.
- AI 열쇠·비밀번호·토큰을 코드, 커밋, 캡처, 도움정보에 넣지 않습니다. 주소나 열쇠를 직접 입력하는 칸도 만들지 않습니다.
- .env.example에는 비밀 없는 설정만 있습니다.

## 더 읽을 곳

- 단계별 안내와 AI에 붙여 넣을 문장: docs/STUDENT_PROMPTS.md
- 단계별 확인 항목: docs/CURRICULUM.json, docs/IMPLEMENTATION_CONTRACT.md
- 오류 코드별 해결: docs/CONNECTION_TROUBLESHOOT.md
- 시작 틀 업데이트(내 파일 보존): docs/STARTER_UPDATE.md
- 실제 회사 시스템(SDP)·앱 안 AI 연결은 담당자가 따로 안내할 때만 씁니다: docs/SDP_HOST_CONNECTION.md, docs/AI_SETUP_GUIDE.md. 이 연결은 앱을 처음 켜고 13~16단계 화면을 만들거나 공식 AI 코드 판정을 받기 위한 전제 조건은 아닙니다. 다만 17단계 이후의 실제 연결과 새 환경 재현은 해당 단계의 기준에 따라 따로 확인합니다.

---

## 학생 부분 (21단계, 학생 작성)

> 이 아래는 학생이 덧붙인 부분입니다. 위의 제공 README 내용은 고치지 않았습니다. 자세한 실행 절차·구성도·장애 안내·미확인 항목은 [docs/STUDENT_RUNBOOK.md](docs/STUDENT_RUNBOOK.md)에 있습니다.

### 목적

케셰브는 회사 직원이 **자기 자신의** 로그인·기기·세션 상태, 업무 앱 접근 판정, 최근 접속 기록과 보안 경보, AI 사건 설명, 보안 조치 진행 상태, 설치 패키지의 알려진 취약점을 한 화면에서 확인하는 보안 앱입니다. 확인할 수 없는 상태는 정상이나 안전으로 바꾸지 않고 「확인 불가」로 보여 줍니다.

### 기능 (학생이 `student/extension.mjs`에 작성)

| 단계 | 함수 | 메뉴 | 기능 |
|---|---|---|---|
| 13 | `renderIdentity` | 보호 현황 | 로그인 사용자·기기·세션 표시, 실패 시 옛 값 제거 |
| 14 | `renderDecision` | 업무 앱 | 접근 허용·거부·추가 확인·확인 불가와 요청 실패 구분 |
| 15 | `renderEvents` | 보안 기록 | 접속 기록·XDR 경보 목록, 필터 3개, 상세 |
| 16 | `renderStatus` (+15단계 상세) | 보호 현황 | 알림·빈 화면·오류·시간 초과, 도움정보 복사, 미지원 조치 안내 |
| 17 | `renderAiConnection` | 보호 현황 | 앱 안 AI 연결 점검 결과와 오류 원인별 안내 |
| 18 | `renderExplanation` | 보안 기록 | 근거·규칙·확인 불가 상태에 연결된 AI 사건 설명 |
| 19 | `renderAction` | 보안 기록 | 제안·사람 확인·전달·접수·효과 확인 구분 |
| 20 | `renderVulnerabilities` | 보호 현황 | 정확한 설치 버전과 OSV 조회 결과, 미조회·일부 실패 구분 |

### 구성

브라우저(`public/index.html`·`public/app.js` + 학생 `student/extension.mjs`) → 로컬 앱 서버(`src/server.mjs`, `http://127.0.0.1:5189`) → ① 접근 제어·XDR 시스템(`student/engine-adapter.mjs` 경유, 기본 실행은 연결 없음, `--demo`는 예제 엔진) ② AI 게이트웨이 CLCO(`src/ai/*`) ③ OSV 공개 취약점 DB(`src/vulnerabilities/*`) ④ 조치 연동 시스템(`src/actions/*`, 현재 미연결). 그림(Mermaid)과 글 구성도는 `docs/STUDENT_RUNBOOK.md` 5장에 있습니다.

제공 코드(`public/`, `src/`, `tools/`, `vendor/`, `student/engine-adapter.mjs`, 제공 문서)는 고치지 않았습니다. 학생이 작성한 것은 `student/extension.mjs`, `docs/STUDENT_RUNBOOK.md`, 이 「학생 부분」입니다.

### 지원 환경과 버전

| 항목 | 값 | 확인 상태 |
|---|---|---|
| 시작 틀 | `alekov-client-starter` 0.2.11 (`package.json`) | 코드로 확인 |
| Node.js | 수업 기준 24.19.0 (`package.json` `engines`), 실행 도구는 22~24 허용 | v22.22.0(리눅스)에서 `node src/server.mjs`·`--demo` 실행 확인, 24.19.0·Windows는 미확인 |
| 외부 npm 패키지 | 없음 | 코드로 확인 |
| 실행 | 앱 폴더(`on-client`)에서 `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1` 또는 `npm start` / 예제 `npm run demo` | `npm start`·`npm run demo`에 해당하는 명령은 실행 확인, PowerShell 실행 도구는 미확인 |
| 브라우저 주소 | http://127.0.0.1:5189/ | 확인함 |
| 종료 | 실행한 창에서 `Ctrl+C` | — |

실제 회사 시스템 연결, 실제 AI 사건 설명 성공, 실제 보안 조치 집행, 실제 패키지 표 조회는 담당자 준비가 필요해 **확인하지 못했습니다**(`docs/STUDENT_RUNBOOK.md` 9장).

### 재현 기록과 버전 (22단계)

- 새 폴더에서 최종 코드 커밋을 받아 실행·종료·재실행한 기록, 13~21단계별 결과, 데이터 보존·백업·복원 계획: [docs/STUDENT_REPRODUCTION.md](docs/STUDENT_REPRODUCTION.md)
- 버전(0.9.0, 검증 중인 버전)·지원 범위·누락·미해결 사항: [docs/RELEASE.md](docs/RELEASE.md)
- 22단계 통과는 원문 검토 기준의 수료이며 실제 운영 인증이 아닙니다.
