# nginx 취약점 점검 스크립트 (윈도우용)
# 주요정보통신기반시설 가이드 2026 (WEB-01 ~ WEB-26)
# 관리자 권한 PowerShell 에서 실행
# 실행방법 : powershell -ExecutionPolicy Bypass -File .\nginx_check.ps1 [-NGINX C:\nginx]
#   경로 안 쓰면 실행중인 nginx 에서 찾고, 그래도 없으면 C:\nginx
# 결과는 nginx_result_<컴퓨터이름>.txt 에 저장됨 (UTF-8)
# 점검만 하고 설정은 하나도 안 바꿈
#
# 처음 버전에서 고친거
#  1. nginx.conf 파일 전체를 Select-String 으로 찾았더니 주석(#)에 있는 글자도 걸리고
#     "ssl" 처럼 짧은 글자는 아무데나 걸렸음
#     -> 주석 지우고 지시자(이름 + 값) 단위로 잘라서 봄 (Parse-Nginx 함수)
#  2. include 로 다른 파일에 나눠 쓴 설정은 못 봤음 -> nginx -T 로 합쳐진 전체 설정을 봄
#  3. 리디렉션, 에러페이지는 server 블록마다 봐야 되는데 파일 전체에서 한번만 찾았음
#     -> 지시자마다 몇번째 server 블록 안에 있는지 기록해서 server 별로 판단
#  4. 권한(ACL) 볼때 "Users" 글자로 찾던거 -> SID 로 일반 사용자 그룹을 찾음
#  5. nginx 가 꺼져있으면 실행 계정을 못 봤었는데 서비스/예약작업 설정에서 실행 계정을 찾음

param(
    [string]$NGINX = ""
)

$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "관리자 권한으로 실행하세요!!"
    exit 1
}

# nginx 경로 찾기 : 직접 쓴 경로 -> 실행중인 nginx.exe 위치 -> C:\nginx
if (-not $NGINX) {
    $p = Get-Process nginx -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($p -and $p.Path) { $NGINX = Split-Path $p.Path }
}
if (-not $NGINX) { $NGINX = "C:\nginx" }
$NGINX = $NGINX.TrimEnd("\")
if (-not (Test-Path "$NGINX\nginx.exe")) {
    Write-Host "nginx 를 못 찾았음 : $NGINX"
    Write-Host "경로를 직접 써주세요  예) .\nginx_check.ps1 -NGINX D:\nginx"
    exit 1
}

$RESULT = Join-Path (Get-Location) "nginx_result_$($env:COMPUTERNAME).txt"
Set-Content -Path $RESULT -Value "nginx 취약점 점검 결과" -Encoding UTF8


#==========================================================
# 함수
#==========================================================

function Write-Result($text) {
    Add-Content -Path $RESULT -Value $text -Encoding UTF8
}

function Title($code, $name) {
    Write-Result ""
    Write-Result "[$code] $name"
}

function Log($text) {
    foreach ($t in @($text)) {
        Write-Result ("  $t" -replace "[\x00-\x08\x0B\x0C\x0E-\x1F]", "")
    }
}

function Result($r) {
    Write-Result "결과 : $r"
}

# nginx 설정을 지시자 목록으로 만들기
#  - # 부터 줄 끝까지는 주석이라 지움
#  - { } ; 기준으로 잘라서 "이름 값" 하나씩 만듦
#  - 각 지시자가 몇번째 server 블록 안에 있는지(Server), 어느 블록 안인지(Ctx) 같이 기록
#    (server 밖이면 Server = 0)
function Parse-Nginx($text) {
    $clean = ($text -split "`r?`n" | ForEach-Object { $_ -replace '(^|\s)#.*$', '' }) -join "`n"
    $list = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.ArrayList
    $serverNo = 0
    $cur = 0
    $buf = ""
    foreach ($m in [regex]::Matches($clean, '[^{};]+|[{};]')) {
        $v = $m.Value
        if ($v -eq "{") {
            $head = $buf.Trim()
            [void]$stack.Add($head)
            # upstream 안의 "server 주소;" 는 블록이 아니라서 "server {" 만 server 블록으로 셈
            if ($head -eq "server") {
                $serverNo++
                $cur = $serverNo
            }
            $buf = ""
        } elseif ($v -eq "}") {
            if ($stack.Count -gt 0) {
                $last = $stack[$stack.Count - 1]
                $stack.RemoveAt($stack.Count - 1)
                if ($last -eq "server") { $cur = 0 }
            }
            $buf = ""
        } elseif ($v -eq ";") {
            $d = $buf.Trim()
            if ($d) {
                $parts = $d -split "\s+", 2
                $argv = ""
                if ($parts.Count -gt 1) { $argv = $parts[1] }
                [void]$list.Add([pscustomobject]@{ Server = $cur; Ctx = ($stack -join " > "); Name = $parts[0]; Args = $argv })
            }
            $buf = ""
        } else {
            $buf += $v
        }
    }
    return $list
}

# 지시자 찾기 (이름으로)
# 처음에 함수 이름을 Dir 로 했다가 파워쉘 기본 명령어(dir = Get-ChildItem)가 먼저 실행돼서 이름 바꿈
# 받을때는 꼭 @( ) 로 감싸야 됨 : 결과가 1개면 배열이 아니라서 파워쉘 5.1 에서 .Count 가 안나옴
function Directive($name) {
    return @($CONF | Where-Object { $_.Name -eq $name })
}

# server 블록 번호 목록
function ServerList() {
    return @($CONF | Where-Object { $_.Server -gt 0 } | Select-Object -ExpandProperty Server -Unique)
}

# server 블록 이름 (server_name 첫번째, 없으면 몇번째 server 인지)
function ServerName($no) {
    $sn = $CONF | Where-Object { $_.Server -eq $no -and $_.Name -eq "server_name" } | Select-Object -First 1
    if ($sn) { return "$($sn.Args) (server #$no)" }
    return "server #$no"
}

# 폴더 권한(ACL)에서 일반 사용자 그룹이 가진 권한 찾기
# Everyone(S-1-1-0), Users(S-1-5-32-545), Authenticated Users(S-1-5-11), Guests(S-1-5-32-546), INTERACTIVE(S-1-5-4)
function UserAcl($path) {
    $normal = @("S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-32-546", "S-1-5-4")
    $acl = Get-Acl -Path $path -ErrorAction SilentlyContinue
    $found = @()
    if (-not $acl) { return $found }
    foreach ($a in $acl.Access) {
        if ($a.AccessControlType -ne "Allow") { continue }
        try { $sid = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $sid = "" }
        if ($normal -contains $sid) { $found += "$($a.IdentityReference) ($($a.FileSystemRights))" }
    }
    return $found
}

# 관리자급 계정인지 (SYSTEM, LocalSystem, Administrators 그룹 구성원)
function IsAdminAccount($name) {
    if (-not $name) { return $false }
    if ($name -match "^(NT AUTHORITY\\)?SYSTEM$|LocalSystem|^S-1-5-18$") { return $true }
    $short = ($name -split "\\")[-1]
    $admins = @(Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction SilentlyContinue | ForEach-Object { ($_.Name -split "\\")[-1] })
    return ($admins -contains $short)
}


#==========================================================
# 설정 읽기
#==========================================================
# nginx -T : include 된 파일까지 합쳐서 전체 설정을 보여줌 (설정만 보고 서버는 안 건드림)
# 실패하면(문법 오류 등) nginx.conf 파일만 직접 읽음
$raw = cmd /c "cd /d `"$NGINX`" && nginx.exe -T 2>&1"
$conf_ok = ($raw -match "test is successful")
if ($conf_ok) {
    # "nginx: ..." 로 시작하는 줄은 nginx 메시지라 설정에서 뺌
    $text = ($raw | Where-Object { $_ -notmatch "^nginx: " }) -join "`n"
} else {
    $text = Get-Content "$NGINX\conf\nginx.conf" -Raw
}
$CONF = Parse-Nginx $text
$SERVERS = @(ServerList)
$VER = (cmd /c "`"$NGINX\nginx.exe`" -v 2>&1") -join " "

Write-Result "점검 날짜 : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Result "컴퓨터 이름 : $($env:COMPUTERNAME)"
Write-Result "nginx 경로 : $NGINX"
Write-Result "nginx 버전 : $VER"
if ($conf_ok) {
    Write-Result "설정 : nginx -T 로 읽음 (include 포함), server 블록 $($SERVERS.Count) 개"
} else {
    Write-Result "설정 : nginx -T 실패해서 nginx.conf 만 읽음 (include 된 파일은 못 봄)"
}

Write-Host "점검 시작!!"


Write-Result ""
Write-Result "===================== 1. 계정 관리 ====================="

Title "WEB-01" "Default 관리자 계정명 변경"
Log "가이드에 nginx 점검 방법이 없음 (nginx 는 관리자 페이지/계정이 없음)"
Result "N/A"

Title "WEB-02" "취약한 비밀번호 사용 제한"
Log "가이드에 nginx 점검 방법이 없음"
Result "N/A"

Title "WEB-03" "비밀번호 파일 권한 관리"
Log "가이드에 nginx 점검 방법이 없음"
Result "N/A"


Write-Result ""
Write-Result "===================== 2. 서비스 관리 ====================="

Title "WEB-04" "웹 서비스 디렉터리 리스팅 방지 설정"
$on = @(Directive "autoindex" | Where-Object { $_.Args -eq "on" })
if ($on.Count -eq 0) {
    Log "autoindex on 없음 (기본값 off)"
    Result "양호"
} else {
    foreach ($d in $on) { Log "autoindex on : $($d.Ctx)" }
    Result "취약"
}

Title "WEB-05" "지정하지 않은 CGI/ISAPI 실행 제한"
# nginx 는 CGI 를 직접 못 돌리고 fastcgi/scgi/uwsgi 로 넘김
$cgi = @($CONF | Where-Object { $_.Name -in @("fastcgi_pass", "scgi_pass", "uwsgi_pass") })
if ($cgi.Count -eq 0) {
    Log "CGI 연동 설정 없음"
    Result "양호"
} else {
    foreach ($d in $cgi) { Log "$($d.Name) $($d.Args) : $($d.Ctx)" }
    Log "CGI 실행되는 경로가 제한돼 있는지 확인"
    Result "인터뷰"
}

Title "WEB-06" "웹 서비스 상위 디렉터리 접근 제한 설정"
# 가이드 : 접근 제한할 디렉터리에 auth_basic (기본 인증) 설정
$auth = @(Directive "auth_basic" | Where-Object { $_.Args -ne "off" })
if ($auth.Count -gt 0) {
    foreach ($d in $auth) { Log "auth_basic : $($d.Ctx)" }
    Result "양호"
} else {
    Log "auth_basic 설정 없음 -> 접근 제한이 필요한 디렉터리가 있는지 확인"
    Result "인터뷰"
}

Title "WEB-07" "웹 서비스 경로 내 불필요한 파일 제거"
# 설치할때 같이 깔리는 기본 파일들
$left = @()
foreach ($f in "html\index.html", "html\50x.html", "docs", "contrib") {
    if (Test-Path "$NGINX\$f") { $left += $f }
}
if ($left.Count -eq 0) {
    Result "양호"
} else {
    Log "남아있는 기본 파일 : $($left -join ', ')"
    Result "취약"
}

Title "WEB-08" "웹 서비스 파일 업로드 및 다운로드 용량 제한"
# client_max_body_size. 0 은 제한 없음
$size = @(Directive "client_max_body_size")
if ($size.Count -eq 0) {
    Log "client_max_body_size 설정 없음"
    Result "취약"
} else {
    foreach ($d in $size) { Log "client_max_body_size $($d.Args) : $($d.Ctx)" }
    if (@($size | Where-Object { $_.Args -eq "0" }).Count -gt 0) { Log "0 은 제한 없음"; Result "취약" } else { Result "양호" }
}

Title "WEB-09" "웹 서비스 프로세스 권한 제한"
# 윈도우 nginx 는 nginx.conf 의 user 지시자가 안 먹어서 실제로 누구 권한으로 도는지 봐야됨
# 1) 지금 돌고 있으면 프로세스 계정
# 2) 꺼져 있으면 띄우는 방법(서비스 / 예약 작업)에 적힌 실행 계정
$runas = @()
foreach ($p in (Get-CimInstance Win32_Process -Filter "Name='nginx.exe'")) {
    $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner
    $runas += "$($o.Domain)\$($o.User) (실행중 PID $($p.ProcessId))"
}
if ($runas.Count -eq 0) {
    Log "nginx 지금 안 돌고 있음 -> 서비스/예약 작업 설정에서 실행 계정 찾음"
    foreach ($s in (Get-CimInstance Win32_Service | Where-Object { $_.PathName -like "*nginx*" })) {
        $runas += "$($s.StartName) (서비스 $($s.Name))"
    }
    foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { ($_.Actions | ForEach-Object { $_.Execute }) -like "*nginx*" })) {
        $runas += "$($t.Principal.UserId) (예약 작업 $($t.TaskName))"
    }
}
$adminRun = @($runas | Where-Object { IsAdminAccount (($_ -split " \(")[0]) })
if ($runas.Count -eq 0) {
    Log "실행 계정을 못 찾음"
    Result "인터뷰"
} else {
    foreach ($r in $runas) { Log "실행 계정 : $r" }
    if ($adminRun.Count -gt 0) { Log "관리자 권한으로 구동"; Result "취약" } else { Result "양호" }
}

Title "WEB-10" "불필요한 프록시 설정 제한"
$proxy = @(Directive "proxy_pass")
if ($proxy.Count -eq 0) {
    Log "proxy_pass 없음"
    Result "양호"
} else {
    foreach ($d in $proxy) { Log "proxy_pass $($d.Args) : $($d.Ctx)" }
    Log "필요한 프록시인지 확인"
    Result "인터뷰"
}

Title "WEB-11" "웹 서비스 경로 설정"
# root 가 nginx 설치폴더 안(기본 html)이면 업무 영역이랑 분리 안된걸로 봄
# root 없이 proxy_pass 만 쓰면 nginx 가 직접 보여주는 웹 경로가 없어서 N/A
$roots = @(Directive "root")
if ($roots.Count -eq 0 -and $proxy.Count -gt 0) {
    Log "root 없이 프록시만 사용 (정적 웹 경로 안씀)"
    Result "N/A"
} else {
    $bad = @()
    if ($roots.Count -eq 0) {
        Log "root 설정 없음 -> 기본값 html ($NGINX\html)"
        $bad += "$NGINX\html"
    }
    foreach ($d in $roots) {
        $r = $d.Args.Trim('"', "'")
        # 상대경로(html 같은거)는 nginx 폴더 기준
        if ($r -notmatch "^[A-Za-z]:|^/|^\\") { $r = "$NGINX\$r" }
        $r = $r -replace "/", "\"
        Log "root $($d.Args) -> $r ($($d.Ctx))"
        if ($r -like "$NGINX*" -or $r -like "$env:windir*") { $bad += $r }
    }
    if ($bad.Count -eq 0) { Result "양호" } else { Log "분리 안된 경로 : $($bad -join ', ')"; Result "취약" }
}

Title "WEB-12" "웹 서비스 링크 사용 금지"
# 윈도우는 심볼릭 링크랑 정션이 ReparsePoint 속성으로 나옴
# (리눅스 nginx 의 disable_symlinks 는 윈도우에서 지원 안함)
$webdirs = @("$NGINX\html")
foreach ($d in $roots) {
    $r = $d.Args.Trim('"', "'")
    if ($r -notmatch "^[A-Za-z]:|^/|^\\") { $r = "$NGINX\$r" }
    $webdirs += ($r -replace "/", "\")
}
$links = @()
foreach ($w in ($webdirs | Select-Object -Unique)) {
    if (-not (Test-Path $w)) { continue }
    $links += @(Get-ChildItem $w -Recurse -Force -Attributes ReparsePoint -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
}
if ($links.Count -eq 0) {
    Log "웹 경로 안에 링크 없음 ($(($webdirs | Select-Object -Unique) -join ', '))"
    Result "양호"
} else {
    foreach ($l in $links) { Log "링크 : $l" }
    Result "취약"
}

Title "WEB-13" "웹 서비스 설정 파일 노출 제한"
Log "가이드에 nginx 점검 방법이 없음"
Result "N/A"

Title "WEB-14" "웹 서비스 경로 내 파일의 접근 통제"
# 일반 사용자 그룹(Users, Everyone 등)이 nginx 폴더, 설정, 웹 경로에 권한이 있으면 취약
$bad = @()
foreach ($d in "$NGINX", "$NGINX\conf", "$NGINX\html") {
    if (-not (Test-Path $d)) { continue }
    $u = UserAcl $d
    Log "$d : $(if ($u) { $u -join ', ' } else { '일반 사용자 권한 없음' })"
    if ($u) { $bad += $d }
}
if ($bad.Count -eq 0) { Result "양호" } else { Result "취약" }

Title "WEB-15" "웹 서비스의 불필요한 스크립트 매핑 제거"
Log "가이드에 nginx 점검 방법이 없음"
Result "N/A"

Title "WEB-16" "웹 서비스 헤더 정보 노출 제한"
# server_tokens 기본값이 on 이라 off 를 꼭 써야 버전이 안나옴
# http 블록에 off 가 있으면 전체 적용, 아니면 server 마다 있어야 됨
$tok = @(Directive "server_tokens")
foreach ($d in $tok) { Log "server_tokens $($d.Args) : $($d.Ctx)" }
$httpOff = @($tok | Where-Object { $_.Server -eq 0 -and $_.Args -eq "off" }).Count -gt 0
$noOff = @()
foreach ($s in $SERVERS) {
    $sv = $tok | Where-Object { $_.Server -eq $s } | Select-Object -Last 1
    if ($sv) {
        if ($sv.Args -ne "off") { $noOff += (ServerName $s) }
    } elseif (-not $httpOff) {
        $noOff += (ServerName $s)
    }
}
# 돌고 있으면 실제 응답 헤더도 봄
if (Get-Process nginx -ErrorAction SilentlyContinue) {
    try {
        $listen = (Directive "listen" | Select-Object -First 1).Args -replace "[^0-9]", ""
        if (-not $listen) { $listen = "80" }
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$listen/" -UseBasicParsing -TimeoutSec 5 -MaximumRedirection 0 -ErrorAction SilentlyContinue
        Log "실제 응답 Server 헤더 : $($resp.Headers['Server'])"
    } catch {
        $h = $_.Exception.Response.Headers["Server"]
        if ($h) { Log "실제 응답 Server 헤더 : $h" }
    }
}
if ($tok.Count -eq 0) { Log "server_tokens off 없음 (기본값은 버전 노출)" }
if ($noOff.Count -eq 0 -and ($httpOff -or $SERVERS.Count -gt 0) -and $tok.Count -gt 0) {
    Result "양호"
} else {
    if ($noOff.Count -gt 0) { Log "버전 노출되는 server : $($noOff -join ', ')" }
    Result "취약"
}

Title "WEB-17" "가상 디렉터리"
$alias = @(Directive "alias")
if ($alias.Count -eq 0) {
    Log "alias 없음"
    Result "양호"
} else {
    foreach ($d in $alias) { Log "alias $($d.Args) : $($d.Ctx)" }
    Log "필요한 가상 디렉터리인지 확인"
    Result "인터뷰"
}

Title "WEB-18" "웹 서비스 WebDAV 비활성화"
$dav = @($CONF | Where-Object { ($_.Name -eq "dav_methods" -and $_.Args -ne "off") -or $_.Name -eq "dav_ext_methods" })
if ($dav.Count -eq 0) {
    Log "WebDAV(dav_methods) 설정 없음"
    Result "양호"
} else {
    foreach ($d in $dav) { Log "$($d.Name) $($d.Args) : $($d.Ctx)" }
    Result "취약"
}


Write-Result ""
Write-Result "===================== 3. 보안 설정 ====================="

Title "WEB-19" "웹 서비스 SSI 사용 제한"
$ssi = @(Directive "ssi" | Where-Object { $_.Args -eq "on" })
if ($ssi.Count -eq 0) {
    Log "ssi on 없음 (기본값 off)"
    Result "양호"
} else {
    foreach ($d in $ssi) { Log "ssi on : $($d.Ctx)" }
    Result "취약"
}

Title "WEB-20" "SSL/TLS 활성화"
# listen 443 ssl 처럼 listen 에 ssl 이 있거나 (옛날 방식) ssl on 이 있는 server 가 있어야 됨
# 쓰고 있으면 ssl_protocols 에 옛날 버전(SSLv3, TLSv1, TLSv1.1)이 있는지도 봄
$sslServers = @()
foreach ($s in $SERVERS) {
    $l = @($CONF | Where-Object { $_.Server -eq $s -and (($_.Name -eq "listen" -and $_.Args -match "(^|\s)ssl(\s|$)") -or ($_.Name -eq "ssl" -and $_.Args -eq "on")) })
    if ($l.Count -gt 0) { $sslServers += $s }
}
if ($sslServers.Count -eq 0) {
    Log "SSL/TLS 쓰는 server 없음 (listen 에 ssl 없음)"
    Result "취약"
} else {
    foreach ($s in $sslServers) { Log "SSL 사용 : $(ServerName $s)" }
    $old = @(Directive "ssl_protocols" | Where-Object { $_.Args -match "SSLv2|SSLv3|TLSv1(\s|$)|TLSv1\.1" })
    if ($old.Count -gt 0) {
        foreach ($d in $old) { Log "옛날 프로토콜 허용 : ssl_protocols $($d.Args)" }
        Result "취약"
    } else {
        Result "양호"
    }
}

Title "WEB-21" "HTTP 리디렉션"
# ssl 없는(HTTP) server 마다 return 301 https... 나 rewrite ... https 로 보내는지
$noRedir = @()
foreach ($s in $SERVERS) {
    if ($sslServers -contains $s) { continue }
    $r = @($CONF | Where-Object { $_.Server -eq $s -and (($_.Name -eq "return" -and $_.Args -match "^30[178]\s+https://") -or ($_.Name -eq "rewrite" -and $_.Args -match "https://")) })
    Log "HTTP server $(ServerName $s) : $(if ($r) { 'HTTPS 리디렉션 있음' } else { 'HTTPS 리디렉션 없음' })"
    if ($r.Count -eq 0) { $noRedir += (ServerName $s) }
}
if ($SERVERS.Count -eq 0) {
    Log "server 블록 없음"
    Result "N/A"
} elseif ($noRedir.Count -eq 0) {
    Result "양호"
} else {
    Result "취약"
}

Title "WEB-22" "에러 페이지 관리"
# http 블록에 error_page 가 있으면 전체 적용, 아니면 server 마다 있어야 됨
$ep = @(Directive "error_page")
foreach ($d in $ep) { Log "error_page $($d.Args) : $($d.Ctx)" }
$httpEp = @($ep | Where-Object { $_.Server -eq 0 }).Count -gt 0
$noEp = @()
foreach ($s in $SERVERS) {
    if (-not $httpEp -and @($ep | Where-Object { $_.Server -eq $s }).Count -eq 0) { $noEp += (ServerName $s) }
}
if ($ep.Count -gt 0 -and $noEp.Count -eq 0) {
    Result "양호"
} else {
    Log "error_page 없는 server : $(if ($noEp) { $noEp -join ', ' } else { '전체' })"
    Result "취약"
}

Title "WEB-23" "LDAP 알고리즘 적절하게 구성"
Log "가이드에 nginx 점검 방법이 없음"
Result "N/A"

Title "WEB-24" "별도의 업로드 경로 사용 및 권한 설정"
# nginx 설정에 upload 들어간 location 이 있으면 보여주고, 프록시면 뒤쪽 WAS 에서 업로드를 받음
$up = @($CONF | Where-Object { $_.Ctx -match "location[^>]*upload" } | Select-Object -ExpandProperty Ctx -Unique)
foreach ($u in $up) { Log "업로드 location : $u" }
if ($proxy.Count -gt 0) { Log "프록시로 넘기고 있어서 업로드는 뒤쪽 서버(WAS)에서 처리 -> WAS 점검 결과도 같이 확인" }
Log "업로드 경로를 웹 경로 밖에 따로 쓰는지 담당자 확인"
Result "인터뷰"


Write-Result ""
Write-Result "===================== 4. 패치 및 로그 관리 ====================="

Title "WEB-25" "주기적 보안 패치 및 벤더 권고사항 적용"
Log "현재 버전 : $VER"
Log "https://nginx.org/en/download.html 최신 버전이랑 비교 필요"
Result "인터뷰"

Title "WEB-26" "로그 디렉터리 및 파일 권한 설정"
# 기본 logs 폴더 + access_log, error_log 로 따로 지정한 폴더
$logdirs = @("$NGINX\logs")
foreach ($d in ($CONF | Where-Object { $_.Name -in @("access_log", "error_log") })) {
    $f = ($d.Args -split "\s+")[0].Trim('"', "'")
    if ($f -eq "off" -or $f -like "syslog:*") { continue }
    if ($f -notmatch "^[A-Za-z]:|^/|^\\") { $f = "$NGINX\$f" }
    $logdirs += (Split-Path ($f -replace "/", "\"))
}
$bad = @()
foreach ($d in ($logdirs | Select-Object -Unique)) {
    if (-not (Test-Path $d)) { continue }
    $u = UserAcl $d
    Log "$d : $(if ($u) { $u -join ', ' } else { '일반 사용자 권한 없음' })"
    if ($u) { $bad += $d }
}
if ($bad.Count -eq 0) { Result "양호" } else { Result "취약" }


#==========================================================
# 개수 세기
#==========================================================
$lines = Get-Content $RESULT -Encoding UTF8
$good = @($lines | Where-Object { $_ -eq "결과 : 양호" }).Count
$badc = @($lines | Where-Object { $_ -eq "결과 : 취약" }).Count
$ask = @($lines | Where-Object { $_ -eq "결과 : 인터뷰" }).Count
$na = @($lines | Where-Object { $_ -eq "결과 : N/A" }).Count
$code = ""
$askList = @()
$badList = @()
foreach ($l in $lines) {
    if ($l -match "^\[(WEB-\d+)\]") { $code = $Matches[1] }
    if ($l -eq "결과 : 인터뷰") { $askList += $code }
    if ($l -eq "결과 : 취약") { $badList += $code }
}

Write-Result ""
Write-Result "======================================"
Write-Result "양호 : $good"
Write-Result "취약 : $badc"
Write-Result "인터뷰 : $ask"
Write-Result "N/A : $na"
Write-Result "취약 항목 : $($badList -join ' ')"
Write-Result "인터뷰 항목 : $($askList -join ' ')"

Write-Host "점검 끝!!"
Write-Host "양호 : $good   취약 : $badc   인터뷰 : $ask   N/A : $na"
Write-Host "결과는 $RESULT 파일 보세요"
