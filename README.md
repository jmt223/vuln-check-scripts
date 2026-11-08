# 취약점 진단 스크립트

「2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」 기준으로 서버 설정을 점검하는 스크립트입니다.
점검만 하고 설정은 바꾸지 않습니다.

## 스크립트

| 파일 | 대상 | 점검 항목 |
|---|---|---|
| `unix_check.sh` | Linux (Rocky 9) | U-01 ~ U-67 |
| `tomcat_check.sh` | Tomcat | WEB-01 ~ WEB-26 |
| `mysql_check.sh` | MySQL 8.0 | D-01 ~ D-26 |
| `windows_check.ps1` | Windows Server 2022 | W-01 ~ W-64 (IIS 항목 W-19, W-26 제외) |
| `nginx_check.ps1` | nginx (Windows) | WEB-01 ~ WEB-26 |

## 실행 방법

Linux (root 권한 필요)

```bash
sudo bash unix_check.sh
sudo bash tomcat_check.sh            # 톰캣 경로 자동 탐지, 직접 지정: sudo bash tomcat_check.sh /opt/tomcat
sudo bash mysql_check.sh             # 실행하면 MySQL root 비밀번호 입력 (화면에 안 보임)
```

Windows (관리자 권한 PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File .\windows_check.ps1
powershell -ExecutionPolicy Bypass -File .\nginx_check.ps1     # 경로 지정: -NGINX C:\nginx
```

## 결과

- 실행한 폴더에 `<대상>_result_<서버IP 또는 컴퓨터이름>.txt` 로 저장됩니다.
- 항목마다 `결과 : 양호 / 취약 / 인터뷰 / N/A` 로 판정합니다.
  - 인터뷰 : 담당자 확인이 필요한 항목 (필요한 계정인지, 패치 절차가 있는지 등)
  - N/A : 해당 서비스를 안 쓰거나 가이드에 점검 방법이 없는 항목
- 결과 파일 마지막에 개수와 취약 / 인터뷰 항목 번호가 정리됩니다.
- Linux 결과 파일은 계정 정보가 들어있어서 root 만 읽을 수 있습니다 (`sudo cat` 으로 보기).

`결과/` 폴더에는 테스트 서버에서 돌린 결과와 인터뷰 항목 모음이 있습니다.

## 테스트 환경

Rocky Linux 9.7 / 9.5, Tomcat 10.1.54, MySQL 8.0.46, Windows Server 2022, nginx 1.30.0
