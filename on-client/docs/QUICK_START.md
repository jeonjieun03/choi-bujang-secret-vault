# 케셰브 실행 안내 (한 장)

처음 보는 사람이 이 안내만 보고 케셰브를 켜는 순서입니다. Windows PC의 PowerShell 기준입니다. 설치 프로그램이나 관리자 권한은 필요 없습니다.

## 1. 준비물 확인

시작 메뉴에서 `powershell`을 입력해 **Windows PowerShell**을 엽니다. 아래 두 줄을 한 줄씩 붙여 넣습니다.

```powershell
node --version
git --version
```

- `v22.x.x` ~ `v24.x.x`가 나오면 됩니다(수업 기준 `v24.19.0`). 없거나 다른 버전이면 https://nodejs.org 에서 Node.js 24를 설치하고 **PowerShell 창을 새로 엽니다**.
- `git version …`이 나오면 됩니다. 없으면 https://git-scm.com 에서 설치합니다.

## 2. 프로젝트 받기 (처음 한 번)

```powershell
cd $HOME\Documents
git clone --branch keshev-submit https://github.com/jeonjieun03/choi-bujang-secret-vault.git keshev
```

- 끝나면 `문서\keshev` 폴더가 생깁니다.
- `already exists`가 나오면 같은 이름의 폴더가 이미 있다는 뜻입니다. 그 폴더는 지우지 말고, 마지막 `keshev`를 `keshev-test`처럼 다른 이름으로 바꿔 다시 실행합니다. 이후 안내의 `keshev`도 같은 이름으로 바꿉니다.

## 3. 앱 폴더로 이동 (PowerShell을 열 때마다 먼저)

```powershell
cd $HOME\Documents\keshev\on-client
```

줄 앞이 `PS C:\Users\(내 이름)\Documents\keshev\on-client>`로 바뀌면 맞습니다.
**이 줄을 빼면 4번에서 `-File 매개 변수에 대한 인수 … 없습니다` 오류가 납니다**(새 PowerShell은 `C:\WINDOWS\system32`에서 시작하기 때문).

## 4. 켜기

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1
```

아래 문구가 보이면 켜진 것입니다. **이 창은 앱을 쓰는 동안 닫지 않습니다.**

```
케셰브가 켜졌습니다. 브라우저에서 http://127.0.0.1:5189/ 을 여세요.
서버가 응답한 것만 확인했습니다. AI 연결 상태는 화면에서 따로 확인해 주세요.
끄려면 이 창에서 Ctrl+C 를 누르세요.
```

`-ExecutionPolicy Bypass`는 이번 한 번의 실행에만 적용되며 PC 설정을 바꾸지 않습니다.

## 5. 첫 화면 확인

1. 브라우저 주소창에 `http://127.0.0.1:5189/` 를 입력합니다.
2. 왼쪽 메뉴 「보호 현황」 · 「업무 앱」 · 「보안 기록」이 보이면 정상입니다.
3. 위쪽의 **「연결 없음」**과 빨간 안내(「기존 서버·에이전트의 연결을 확인할 수 없습니다」)는 **정상**입니다. 회사 서버(SDP)에 연결하지 않고 켰기 때문입니다.
4. 「학생 상태·알림 표시」 칸의 **「내 PC 조회」**를 누르면 이 PC의 CPU·메모리·디스크·방화벽 값과 잰 시각이 나옵니다. 그 뒤 「다시 조회」를 누르면 변화(▲▼)와 기록이 쌓입니다.

## 6. 끄기와 다시 켜기

- **끄기:** 4번 PowerShell 창에서 `Ctrl + C`.
- **다시 켜기:** 새 PowerShell 창이면 3번 → 4번, 같은 창이면 4번만.
- **최신 코드 받기:** 3번 위치에서 `git pull` 뒤 4번.

## 7. 막혔을 때

| 보이는 문구 | 원인 | 할 일 |
|---|---|---|
| `-File 매개 변수에 대한 인수 '.\tools\start-alekov.ps1'이(가) 없습니다` | 앱 폴더가 아닌 곳(예: `C:\WINDOWS\system32`)에서 실행 | 3번 `cd` 줄을 먼저 실행 |
| `Node.js 가 없습니다` / `지금 Node.js 는 vXX 입니다` | Node.js가 없거나 22~24가 아님 | Node.js 24 설치 후 PowerShell 창을 새로 열고 3번부터 |
| `'git'은(는) … 인식되지 않습니다` | Git이 없음 | Git 설치 후 PowerShell 창을 새로 열고 2번부터 |
| `포트 5189 를 다른 프로그램이 쓰고 있습니다` | 이미 켜 둔 케셰브 창이 있거나 다른 프로그램이 사용 | 다른 PowerShell 창의 케셰브를 `Ctrl + C`로 끄거나, 4번 명령 끝에 ` -Port 5190`을 붙이고 주소도 `:5190`으로 엽니다 |
| 브라우저에 「사이트에 연결할 수 없음」 | 앱이 꺼져 있음 | 4번 창이 열려 있는지 확인하고 다시 켭니다 |
| 학생 칸에 「조회 실패: 앱 서버에 연결할 수 없음」 | 앱을 끈 뒤 버튼을 누름 | 4번으로 다시 켜고 「다시 조회」 |
| 「내 PC 상태」 카드가 모두 「이번 조회 확인 불가」 | 브라우저 탭을 보지 않는 동안 제공 카드가 자동 확인을 멈춤 | 화면을 보면서 「내 PC 확인」을 누릅니다 |

더 자세한 설명과 구성도는 [STUDENT_RUNBOOK.md](STUDENT_RUNBOOK.md)에 있습니다.
