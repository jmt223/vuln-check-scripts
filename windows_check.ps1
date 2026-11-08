# 윈도우 취약점 점검 스크립트
# 주요정보통신기반시설 가이드 2026 (W-01 ~ W-64)
# W-19, W-26 은 IIS 항목이라 뺌 (IIS 안씀, FTP 는 넣음)
# 실행방법 : 관리자 권한 PowerShell 에서
#   powershell -ExecutionPolicy Bypass -File .\windows_check.ps1
# 결과는 windows_result_<컴퓨터이름>.txt 에 저장됨 (UTF-8)
# 점검만 하고 설정은 하나도 안 바꿈
#
# 처음 버전에서 고친거
#  1. 결과 찍는 코드가 계속 반복돼서 함수로 뺌 (Title / Log / Result)
#  2. reg query 결과를 -like "*0x1*" 로 비교했더니 0x10, 0x1e 같은 값도 걸림
#     -> Get-ItemProperty 로 값을 숫자 그대로 가져와서 비교 (RegVal 함수)
#  3. secedit 값 가져올때 이름이 비슷한게 같이 걸리는거 막음 (SecVal 함수)
#  4. 사용자 권한 정책은 *S-1-5-32-544 같은 SID 로 나와서 이름으로 바꿔서 판단 (SidName 함수)
#  5. Everyone 찾을때 "Everyone" 글자 말고 SID(S-1-1-0)로 찾음 (윈도우 언어마다 이름이 다를수 있어서)
#  6. secpol 파일을 C:\ 에 만들었었는데 임시폴더에 만들고 읽자마자 지움
#  7. $null -ne "" 가 True 라서 값이 아예 없어도 양호로 나오던거 고침 (W-57)

# 관리자 권한인지 확인
$me = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "관리자 권한으로 실행하세요!! (PowerShell 우클릭 -> 관리자 권한으로 실행)"
    exit 1
}

$RESULT = Join-Path (Get-Location) "windows_result_$($env:COMPUTERNAME).txt"
Set-Content -Path $RESULT -Value "윈도우 취약점 점검 결과" -Encoding UTF8


#==========================================================
# 함수
#==========================================================

function Write-Result($text) {
    Add-Content -Path $RESULT -Value $text -Encoding UTF8
}

# 항목 제목
function Title($code, $name) {
    Write-Result ""
    Write-Result "[$code] $name"
}

# 결과파일에 내용 남기기 (앞에 공백 2칸)
# 레지스트리 값에 NUL 같은 제어문자가 들어있으면 결과파일이 바이너리로 보여서 지우고 씀
function Log($text) {
    foreach ($t in @($text)) {
        Write-Result ("  $t" -replace "[\x00-\x08\x0B\x0C\x0E-\x1F]", "")
    }
}

# 판정 (양호 / 취약 / 인터뷰 / N/A)
function Result($r) {
    Write-Result "결과 : $r"
}

# 로컬 보안 정책(secedit) 값 하나 가져오기. "키 = 값" 에서 값만
# -match "^키\s*=" 로 해서 이름이 비슷한 다른 키는 안 걸리게 함
function SecVal($key) {
    $line = $SEC | Where-Object { $_ -match "^\s*$key\s*=" } | Select-Object -First 1
    if ($line) {
        return ($line -split "=", 2)[1].Trim()
    }
    return $null
}

# 레지스트리 값 가져오기. 없으면 $null
function RegVal($path, $name) {
    $p = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
    if ($p) {
        return $p.$name
    }
    return $null
}

# SID 를 이름으로 바꾸기 (*S-1-5-32-544 -> BUILTIN\Administrators)
function SidName($sid) {
    $sid = $sid.Trim().TrimStart("*")
    try {
        return (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value
    } catch {
        return $sid
    }
}

# 폴더/파일 권한(ACL)에 Everyone 이 있는지. 있으면 그 권한 내용을 돌려줌
function EveryoneAcl($path) {
    $acl = Get-Acl -Path $path -ErrorAction SilentlyContinue
    if (-not $acl) { return $null }
    $found = @()
    foreach ($a in $acl.Access) {
        try {
            $sid = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        } catch {
            $sid = ""
        }
        if ($sid -eq "S-1-1-0") {
            $found += "$($a.AccessControlType) $($a.FileSystemRights)"
        }
    }
    return $found
}

# 서비스가 돌고 있는지
function SvcRunning($name) {
    $s = Get-Service -Name $name -ErrorAction SilentlyContinue
    return ($s -and $s.Status -eq "Running")
}


#==========================================================
# 점검 시작
#==========================================================
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
Write-Result "점검 날짜 : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Result "컴퓨터 이름 : $($env:COMPUTERNAME)"
Write-Result "OS : $($os.Caption) (빌드 $($os.BuildNumber))"

# 로컬 보안 정책을 임시파일로 뽑아서 변수에 넣고 파일은 바로 지움
$SECFILE = Join-Path $env:TEMP ("secpol_" + [guid]::NewGuid().ToString("N") + ".inf")
secedit /export /cfg $SECFILE /quiet | Out-Null
$SEC = Get-Content $SECFILE
Remove-Item $SECFILE -Force -ErrorAction SilentlyContinue

# 원격 데스크톱 사용 여부 (fDenyTSConnections = 1 이면 꺼진거) - 여러 항목에서 씀
$RDP_OFF = ((RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections") -eq 1)
# Everyone 그룹 이름 (언어별로 다를수 있어서 SID 로 구함)
$EVERYONE = SidName "S-1-1-0"

Write-Host "점검 시작!!"


Write-Result ""
Write-Result "===================== 1. 계정 관리 ====================="

Title "W-01" "Administrator 계정 이름 변경 등 보안성 강화"
# 이름을 바꿔도 기본 관리자 계정은 SID 끝이 -500 이라서 그걸로 찾음
$adm = Get-LocalUser | Where-Object { $_.SID.Value -like "*-500" }
Log "기본 관리자 계정 이름 : $($adm.Name) (사용 : $($adm.Enabled), 비밀번호 바꾼 날 : $($adm.PasswordLastSet))"
if ($adm.Name -ne "Administrator") {
    Result "양호"
} else {
    # 가이드 : 이름을 바꾸거나 "강화된 비밀번호" 를 쓰면 양호 -> 비밀번호는 스크립트로 못 봐서 인터뷰
    Log "이름이 Administrator 그대로임 -> 강한 비밀번호를 쓰는지 담당자 확인"
    Result "인터뷰"
}

Title "W-02" "Guest 계정 비활성화"
$guest = Get-LocalUser | Where-Object { $_.SID.Value -like "*-501" }
Log "Guest 계정 : $($guest.Name) (사용 : $($guest.Enabled))"
if ($guest.Enabled) {
    Result "취약"
} else {
    Result "양호"
}

Title "W-03" "불필요한 계정 제거"
# 필요한 계정인지는 담당자가 알아야 돼서 켜져있는 계정 목록이랑 마지막 로그인만 보여줌
foreach ($u in (Get-LocalUser | Where-Object { $_.Enabled })) {
    Log "켜져있는 계정 : $($u.Name) (마지막 로그인 : $($u.LastLogon))"
}
Result "인터뷰"

Title "W-04" "계정 잠금 임계값 설정"
# 0 이면 잠금 안함. 1~5 여야 됨
$lock = SecVal "LockoutBadCount"
Log "계정 잠금 임계값 : $lock (0 은 잠금 안함, 5 이하여야 됨)"
if ($lock -and [int]$lock -ge 1 -and [int]$lock -le 5) {
    Result "양호"
} else {
    Result "취약"
}

Title "W-05" "해독 가능한 암호화를 사용하여 암호 저장 해제"
$clear = SecVal "ClearTextPassword"
Log "ClearTextPassword : $clear (0 이 사용 안 함)"
if ($clear -eq "0") {
    Result "양호"
} else {
    Result "취약"
}

Title "W-06" "관리자 그룹에 최소한의 사용자 포함"
# Administrators 그룹 SID 는 S-1-5-32-544
try {
    $members = @(Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop | ForEach-Object { $_.Name })
} catch {
    # 지워진 계정 SID 가 남아있으면 Get-LocalGroupMember 가 에러남 -> net 명령어로
    $members = @(net localgroup administrators | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch "^The command|명령을" })
}
Log "Administrators 구성원 $($members.Count) 명 : $($members -join ', ')"
if ($members.Count -le 1) {
    Result "양호"
} else {
    Log "필요한 관리자 계정인지 확인"
    Result "인터뷰"
}

Title "W-07" "Everyone 사용 권한을 익명 사용자에 적용"
$v = RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous"
Log "EveryoneIncludesAnonymous : $v (0 이 사용 안 함)"
if ($v -eq 0) {
    Result "양호"
} else {
    Result "취약"
}

Title "W-08" "계정 잠금 기간 설정"
# 임계값이 0 이면 이 두 값은 아예 없음 -> 없으면 취약
$dur = SecVal "LockoutDuration"
$reset = SecVal "ResetLockoutCount"
Log "잠금 기간 : $dur 분, 잠금 원래대로 설정 기간 : $reset 분 (둘 다 60 이상, 빈칸은 설정 안됨)"
if ($dur -and $reset -and [int]$dur -ge 60 -and [int]$reset -ge 60) {
    Result "양호"
} else {
    Result "취약"
}

Title "W-09" "비밀번호 관리 정책 설정"
# 기준 : 복잡성 사용, 최근 암호 4개 이상 기억, 최대 사용기간 90일 이하, 최소 사용기간 1일 이상, 최소 길이 8 이상
$complex = SecVal "PasswordComplexity"
$history = SecVal "PasswordHistorySize"
$maxage = SecVal "MaximumPasswordAge"
$minage = SecVal "MinimumPasswordAge"
$minlen = SecVal "MinimumPasswordLength"
Log "복잡성 : $complex  최근 암호 기억 : $history  최대 사용기간 : $maxage  최소 사용기간 : $minage  최소 길이 : $minlen"
$bad = @()
if ($complex -ne "1") { $bad += "복잡성" }
if ([int]$history -lt 4) { $bad += "최근암호기억" }
# 최대 사용기간 -1 이나 0 은 만료 안됨이라 안됨
if ([int]$maxage -lt 1 -or [int]$maxage -gt 90) { $bad += "최대사용기간" }
if ([int]$minage -lt 1) { $bad += "최소사용기간" }
if ([int]$minlen -lt 8) { $bad += "최소길이" }
if ($bad.Count -eq 0) {
    Result "양호"
} else {
    Log "기준 안맞는거 : $($bad -join ', ')"
    Result "취약"
}

Title "W-10" "마지막 사용자 이름 표시 안 함"
$v = RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "dontdisplaylastusername"
Log "dontdisplaylastusername : $v (1 이 사용)"
if ($v -eq 1) {
    Result "양호"
} else {
    Result "취약"
}

Title "W-11" "로컬 로그온 허용"
# Administrators(S-1-5-32-544) 랑 IUSR(S-1-5-17) 만 있어야 됨
$list = SecVal "SeInteractiveLogonRight"
$other = @()
foreach ($s in ($list -split ",")) {
    if (-not $s) { continue }
    $id = $s.Trim().TrimStart("*")
    Log "로컬 로그온 허용 : $(SidName $id)"
    if ($id -ne "S-1-5-32-544" -and $id -ne "S-1-5-17") {
        $other += (SidName $id)
    }
}
if ($other.Count -eq 0) {
    Result "양호"
} else {
    Log "Administrators 말고 있는거 : $($other -join ', ')"
    Result "취약"
}

Title "W-12" "익명 SID/이름 변환 허용 해제"
$anon = SecVal "LSAAnonymousNameLookup"
Log "LSAAnonymousNameLookup : $anon (0 이 사용 안 함)"
if ($anon -eq "0") {
    Result "양호"
} else {
    Result "취약"
}

Title "W-13" "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한"
$v = RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
Log "LimitBlankPasswordUse : $v (1 이 사용)"
if ($v -eq 1) {
    Result "양호"
} else {
    Result "취약"
}

Title "W-14" "원격터미널 접속 가능한 사용자 그룹 제한"
if ($RDP_OFF) {
    Log "원격 데스크톱 안씀"
    Result "N/A"
} else {
    # Remote Desktop Users 그룹 SID 는 S-1-5-32-555
    $rdu = @(Get-LocalGroupMember -SID "S-1-5-32-555" -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    Log "Remote Desktop Users 구성원 : $($rdu -join ', ')"
    if ($rdu.Count -eq 0) {
        # 가이드 : 관리자 말고 원격 접속용 계정을 따로 만들어야 양호
        Log "원격 접속용 계정이 따로 없음 (관리자 계정으로 원격 접속중)"
        Result "취약"
    } else {
        Log "불필요한 계정 없는지 확인"
        Result "인터뷰"
    }
}


Write-Result ""
Write-Result "===================== 2. 서비스 관리 ====================="

Title "W-15" "사용자 개인키 사용 시 암호 입력"
$v = RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography" "ForceKeyProtection"
Log "ForceKeyProtection : $v (2 가 매번 암호 입력, 빈칸은 설정 안됨)"
if ($v -eq 2) {
    Result "양호"
} else {
    Result "취약"
}

Title "W-16" "공유 권한 및 사용자 그룹 설정"
# C$, ADMIN$, IPC$ 같은 기본 공유(Special) 말고 일반 공유만 봄
$shares = @(Get-SmbShare | Where-Object { -not $_.Special })
Log "일반 공유 $($shares.Count) 개"
$bad = @()
foreach ($sh in $shares) {
    $acc = Get-SmbShareAccess -Name $sh.Name | Where-Object { $_.AccountName -eq $EVERYONE -and $_.AccessControlType -eq "Allow" }
    Log "$($sh.Name) ($($sh.Path)) Everyone : $(if ($acc) { $acc.AccessRight } else { '없음' })"
    if ($acc) { $bad += $sh.Name }
}
if ($bad.Count -eq 0) {
    Result "양호"
} else {
    Result "취약"
}

Title "W-17" "하드디스크 기본 공유 제거"
# AutoShareServer 가 0 이어야 되고 C$, ADMIN$ 같은 기본 공유가 없어야 됨 (IPC$ 는 못 지워서 뺌)
$auto = RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareServer"
$def = @(Get-SmbShare | Where-Object { $_.Special -and $_.Name -ne "IPC$" } | ForEach-Object { $_.Name })
Log "AutoShareServer : $auto (0 이어야 됨, 빈칸은 설정 안됨 = 기본 공유 만들어짐)"
Log "기본 공유 : $($def -join ', ')"
if ($auto -eq 0 -and $def.Count -eq 0) {
    Result "양호"
} else {
    Result "취약"
}

Title "W-18" "불필요한 서비스 제거"
# 가이드 "일반적으로 불필요한 서비스" 목록 (윈도우 버전에 따라 없는 서비스도 있음)
$unneed = [ordered]@{
    "Alerter" = "Alerter"; "ClipSrv" = "Clipbook"; "Browser" = "Computer Browser"
    "ERSvc" = "Error Reporting"; "WerSvc" = "Windows Error Reporting"; "hidserv" = "Human Interface Device Access"
    "ImapiService" = "IMAPI CD-Burning COM"; "Irmon" = "Infrared Monitor"; "Messenger" = "Messenger"
    "mnmsrvc" = "NetMeeting Remote Desktop Sharing"; "WmdmPmSN" = "Portable Media Serial Number"
    "RemoteRegistry" = "Remote Registry"; "simptcp" = "Simple TCP/IP Services"
    "upnphost" = "UPnP Device Host"; "WZCSVC" = "Wireless Zero Configuration"
}
$running = @()
foreach ($name in $unneed.Keys) {
    if (SvcRunning $name) { $running += "$name($($unneed[$name]))" }
}
# 상황에 따라 불필요한 서비스 (가이드 설명대로 조건 확인)
#  - Distributed Link Tracking(TrkWks) : AD(도메인) 아니면 불필요
#  - DHCP Client(Dhcp) : 고정 IP 쓰면 불필요
#  - Print Spooler(Spooler) : 프린터 없으면 불필요 (윈도우에 기본으로 있는 PDF/XPS 가상 프린터는 뺌)
# Automatic Updates, Cryptographic Services, DNS Client 는 업데이트/인증서/이름풀이에 써서 여기선 안봄
if (-not $cs.PartOfDomain -and (SvcRunning "TrkWks")) {
    $running += "TrkWks(도메인 아님)"
}
$dhcpNic = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | Where-Object { $_.DHCPEnabled })
if ($dhcpNic.Count -eq 0 -and (SvcRunning "Dhcp")) {
    $running += "Dhcp(고정 IP)"
}
$printers = @(Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.PortName -ne "PORTPROMPT:" -and $_.Name -notlike "Microsoft *" -and $_.Name -notlike "OneNote*" -and $_.Name -notlike "Fax*" })
if ($printers.Count -eq 0 -and (SvcRunning "Spooler")) {
    $running += "Spooler(프린터 없음)"
}
if ($running.Count -eq 0) {
    Log "불필요한 서비스 안 돌고 있음"
    Result "양호"
} else {
    Log "돌고 있는 불필요한 서비스 : $($running -join ', ')"
    Result "취약"
}

Title "W-20" "NetBIOS 바인딩 서비스 구동 점검"
# 네트워크 카드마다 TcpipNetbiosOptions : 0 = DHCP 설정 따름(기본), 1 = 사용, 2 = 사용 안 함
$bad = @()
foreach ($nic in (Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True")) {
    Log "$($nic.Description) : TcpipNetbiosOptions = $($nic.TcpipNetbiosOptions)"
    if ($nic.TcpipNetbiosOptions -ne 2) { $bad += $nic.Description }
}
if ($bad.Count -eq 0) {
    Result "양호"
} else {
    Log "NetBIOS 바인딩 남아있음 (2 = 사용 안 함 이어야 됨)"
    Result "취약"
}

# FTP (W-21 ~ W-24, W-33)
# 윈도우 FTP 는 IIS 에 들어있는 FTPSVC. 설정은 applicationHost.config 에 있음
$FTP_ON = SvcRunning "FTPSVC"
$ftpSites = @()
$iis = $null
if ($FTP_ON) {
    try {
        [xml]$iis = Get-Content "$env:windir\System32\inetsrv\config\applicationHost.config" -ErrorAction Stop
        $siteDefaults = $iis.configuration."system.applicationHost".sites.siteDefaults
        $ftpSites = @($iis.configuration."system.applicationHost".sites.site | Where-Object { $_.bindings.binding.protocol -contains "ftp" })
    } catch {
        $iis = $null
    }
}
# FTP 는 도는데 사이트 설정을 못 읽으면 아래 반복문이 한번도 안 돌아서 전부 양호로 나와버림
# -> 그럴땐 양호 말고 인터뷰로 (FTP_NOCFG)
$FTP_NOCFG = ($FTP_ON -and $ftpSites.Count -eq 0)
$NOCFG_MSG = "FTP 서비스는 도는데 FTP 사이트 설정(applicationHost.config)을 못 읽음 -> 직접 확인"

# FTP 사이트 설정값 (사이트에 없으면 기본값(siteDefaults) 씀)
function FtpSet($site, $part) {
    $v = $site.ftpServer.security.$part
    if (-not $v) { $v = $siteDefaults.ftpServer.security.$part }
    return $v
}

Title "W-21" "암호화되지 않는 FTP 서비스 비활성화"
if (-not $FTP_ON) {
    Log "FTP 안씀"
    Result "양호"
} elseif ($FTP_NOCFG) {
    Log $NOCFG_MSG
    Result "인터뷰"
} else {
    # SSL 정책이 SslRequire 여야 암호화(FTPS) 강제
    $bad = @()
    foreach ($site in $ftpSites) {
        $ssl = FtpSet $site "ssl"
        Log "$($site.name) : 제어채널 $($ssl.controlChannelPolicy), 데이터채널 $($ssl.dataChannelPolicy)"
        if ($ssl.controlChannelPolicy -ne "SslRequire" -or $ssl.dataChannelPolicy -ne "SslRequire") { $bad += $site.name }
    }
    if ($bad.Count -eq 0) { Result "양호" } else { Result "취약" }
}

Title "W-22" "FTP 디렉토리 접근권한 설정"
if (-not $FTP_ON) {
    Log "FTP 안씀"
    Result "N/A"
} elseif ($FTP_NOCFG) {
    Log $NOCFG_MSG
    Result "인터뷰"
} else {
    $bad = @()
    foreach ($site in $ftpSites) {
        $vdir = $site.application.virtualDirectory | Where-Object { $_.path -eq "/" } | Select-Object -First 1
        # $home 은 파워쉘이 쓰는 변수라 이름을 ftpHome 으로 함
        $ftpHome = [Environment]::ExpandEnvironmentVariables($vdir.physicalPath)
        $ev = EveryoneAcl $ftpHome
        Log "$($site.name) 홈 디렉터리 : $ftpHome  Everyone : $(if ($ev) { $ev -join ', ' } else { '없음' })"
        if ($ev) { $bad += $site.name }
    }
    if ($bad.Count -eq 0) { Result "양호" } else { Result "취약" }
}

Title "W-23" "공유 서비스에 대한 익명 접근 제한 설정"
if (-not $FTP_ON) {
    Log "FTP 안씀"
    Result "양호"
} elseif ($FTP_NOCFG) {
    Log $NOCFG_MSG
    Result "인터뷰"
} else {
    $bad = @()
    foreach ($site in $ftpSites) {
        $anon = (FtpSet $site "authentication").anonymousAuthentication.enabled
        Log "$($site.name) 익명 인증 : $anon"
        if ($anon -eq "true") { $bad += $site.name }
    }
    if ($bad.Count -eq 0) { Result "양호" } else { Result "취약" }
}

Title "W-24" "FTP 접근 제어 설정"
if (-not $FTP_ON) {
    Log "FTP 안씀"
    Result "N/A"
} elseif ($FTP_NOCFG) {
    Log $NOCFG_MSG
    Result "인터뷰"
} else {
    # system.ftpServer/security/ipSecurity 의 allowUnlisted="false" 면 허용 IP 만 접속 가능
    $ipsec = $iis.configuration."system.ftpServer".security.ipSecurity
    $locs = @($iis.configuration.location | Where-Object { $_."system.ftpServer".security.ipSecurity })
    Log "전체 ipSecurity allowUnlisted : $($ipsec.allowUnlisted)"
    foreach ($l in $locs) { Log "$($l.path) ipSecurity allowUnlisted : $($l.'system.ftpServer'.security.ipSecurity.allowUnlisted)" }
    $ok = ($ipsec.allowUnlisted -eq "false") -or (@($locs | Where-Object { $_."system.ftpServer".security.ipSecurity.allowUnlisted -eq "false" }).Count -ge $ftpSites.Count)
    if ($ok) { Result "양호" } else { Result "취약" }
}

# DNS (W-25, W-32)
$DNS_ON = SvcRunning "DNS"
$zones = @()
if ($DNS_ON) {
    $zones = @(Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" -ErrorAction SilentlyContinue)
}

Title "W-25" "DNS Zone Transfer 설정"
if (-not $DNS_ON) {
    Log "DNS 서비스 안씀"
    Result "양호"
} else {
    # SecureSecondaries : 0 = 아무 서버나, 1 = 이름서버만, 2 = 지정한 서버만, 3 = 영역 전송 안함
    $bad = @()
    foreach ($z in $zones) {
        $ss = RegVal $z.PSPath "SecureSecondaries"
        Log "$($z.PSChildName) : SecureSecondaries = $ss"
        if ($ss -eq 0) { $bad += $z.PSChildName }
    }
    if ($bad.Count -eq 0) { Result "양호" } else { Result "취약" }
}

Title "W-27" "최신 Windows OS Build 버전 적용"
# 빌드 번호 + 마지막 패치 날짜. 90일 넘게 패치 안했으면 최신 빌드가 아닌걸로 봄
$cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$hot = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
$days = $null
if ($hot) { $days = [int]((Get-Date) - $hot.InstalledOn).TotalDays }
Log "OS 빌드 : $($cv.CurrentBuild).$($cv.UBR) ($($cv.DisplayVersion))"
Log "마지막 패치 : $($hot.HotFixID) ($(if ($hot) { $hot.InstalledOn.ToString('yyyy-MM-dd') }), $days 일 전)"
if ($days -eq $null -or $days -gt 90) {
    Result "취약"
} else {
    Log "최신 빌드인지, 적용 절차가 있는지 담당자 확인"
    Result "인터뷰"
}

Title "W-28" "터미널 서비스 암호화 수준 설정"
if ($RDP_OFF) {
    Log "원격 데스크톱 안씀"
    Result "양호"
} else {
    # MinEncryptionLevel : 1 = 낮음, 2 = 클라이언트 호환(중간), 3 = 높음. 정책에 있으면 정책이 먼저
    $lvl = RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel"
    if ($lvl -eq $null) { $lvl = RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "MinEncryptionLevel" }
    Log "MinEncryptionLevel : $lvl (2 이상이어야 됨)"
    if ($lvl -ge 2) { Result "양호" } else { Result "취약" }
}

# SNMP (W-29 ~ W-31)
$SNMP_ON = SvcRunning "SNMP"
$SNMP_KEY = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters"
$comms = @()
$mgrs = @()
if ($SNMP_ON) {
    $c = Get-Item "$SNMP_KEY\ValidCommunities" -ErrorAction SilentlyContinue
    if ($c) { $comms = @($c.GetValueNames() | Where-Object { $_ }) }
    $m = Get-Item "$SNMP_KEY\PermittedManagers" -ErrorAction SilentlyContinue
    if ($m) { $mgrs = @($m.GetValueNames() | Where-Object { $_ } | ForEach-Object { $m.GetValue($_) }) }
}

Title "W-29" "불필요한 SNMP 서비스 구동 점검"
if (-not $SNMP_ON) {
    Log "SNMP 안씀"
    Result "양호"
} else {
    # 가이드 : Community String 을 설정해서 쓰면 양호
    Log "SNMP 실행중, Community 개수 : $($comms.Count)"
    if ($comms.Count -gt 0) { Result "양호" } else { Result "취약" }
}

Title "W-30" "SNMP Community String 복잡성 설정"
if (-not $SNMP_ON) {
    Log "SNMP 안씀"
    Result "양호"
} else {
    # 커뮤니티 이름은 비밀번호 같은거라 앞 2글자만 남김
    $weak = @($comms | Where-Object { $_ -eq "public" -or $_ -eq "private" })
    foreach ($c in $comms) { Log "Community : $($c.Substring(0, [Math]::Min(2, $c.Length)))*** (길이 $($c.Length))" }
    if ($weak.Count -eq 0) { Result "양호" } else { Log "public/private 사용중"; Result "취약" }
}

Title "W-31" "SNMP Access Control 설정"
if (-not $SNMP_ON) {
    Log "SNMP 안씀"
    Result "양호"
} else {
    # PermittedManagers 가 비어있으면 "모든 호스트로부터 SNMP 패킷 받아들이기"
    Log "SNMP 허용 호스트 : $(if ($mgrs) { $mgrs -join ', ' } else { '없음(모든 호스트 허용)' })"
    if ($mgrs.Count -gt 0) { Result "양호" } else { Result "취약" }
}

Title "W-32" "DNS 서비스 구동 점검"
if (-not $DNS_ON) {
    Log "DNS 서비스 안씀"
    Result "양호"
} else {
    # AllowUpdate : 0 = 동적 업데이트 없음, 1 = 보안 안된것도 허용, 2 = 보안 업데이트만
    $bad = @()
    foreach ($z in $zones) {
        $au = RegVal $z.PSPath "AllowUpdate"
        Log "$($z.PSChildName) : AllowUpdate = $au"
        if ($au -ne 0) { $bad += $z.PSChildName }
    }
    if ($bad.Count -eq 0) { Result "양호" } else { Result "취약" }
}

Title "W-33" "HTTP/FTP/SMTP 배너 차단"
# 가이드 W-33 은 IIS(HTTP), FTP, SMTP 기준. nginx(HTTP) 배너는 nginx 점검(WEB-16)에서 봄
$SMTP_ON = SvcRunning "SMTPSVC"
if (-not $FTP_ON -and -not $SMTP_ON) {
    Log "FTP, SMTP 안씀 (HTTP 는 nginx 점검 WEB-16 참고)"
    Result "N/A"
} else {
    $bad = @()
    $needAsk = $false
    if ($FTP_NOCFG) {
        Log $NOCFG_MSG
        $needAsk = $true
    }
    foreach ($site in $ftpSites) {
        $sup = $site.ftpServer.messages.suppressDefaultBanner
        if (-not $sup) { $sup = $siteDefaults.ftpServer.messages.suppressDefaultBanner }
        Log "FTP $($site.name) 기본 배너 숨김 : $sup"
        if ($sup -ne "true") { $bad += "FTP $($site.name)" }
    }
    if ($SMTP_ON) {
        # SMTP 배너는 IIS6 관리도구(메타베이스)에서 봐야돼서 스크립트로는 확인 못함
        Log "SMTP 서비스 실행중 -> 배너(ConnectResponse) 직접 확인 필요"
        $needAsk = $true
    }
    if ($bad.Count -gt 0) { Result "취약" } elseif ($needAsk) { Result "인터뷰" } else { Result "양호" }
}

Title "W-34" "Telnet 서비스 비활성화"
$tel = Get-Service -Name TlntSvr -ErrorAction SilentlyContinue
if (-not $tel) {
    Log "Telnet 서버 없음"
    Result "N/A"
} elseif ($tel.Status -ne "Running") {
    Log "Telnet 서버 안 돌고 있음"
    Result "양호"
} else {
    # SecurityMechanism : 2 = NTLM 만
    $mech = RegVal "HKLM:\SOFTWARE\Microsoft\TelnetServer\1.0" "SecurityMechanism"
    Log "Telnet 인증 방식 SecurityMechanism : $mech (2 = NTLM)"
    if ($mech -eq 2) { Result "양호" } else { Result "취약" }
}

Title "W-35" "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거"
# 64비트, 32비트 시스템 DSN 둘 다 봄
$dsn = @()
foreach ($k in "HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources", "HKLM:\SOFTWARE\WOW6432Node\ODBC\ODBC.INI\ODBC Data Sources") {
    $item = Get-Item $k -ErrorAction SilentlyContinue
    if ($item) { $dsn += @($item.GetValueNames() | Where-Object { $_ } | ForEach-Object { "$_ ($($item.GetValue($_)))" }) }
}
if ($dsn.Count -eq 0) {
    Log "시스템 DSN 없음"
    Result "양호"
} else {
    Log "시스템 DSN : $($dsn -join ', ')"
    Log "지금 쓰는 데이터 소스인지 확인"
    Result "인터뷰"
}

Title "W-36" "원격터미널 접속 타임아웃 설정"
if ($RDP_OFF) {
    Log "원격 데스크톱 안씀"
    Result "N/A"
} else {
    # MaxIdleTime 은 밀리초. 30분 = 1800000. 정책에 있으면 정책이 먼저
    $idle = RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxIdleTime"
    if ($idle -eq $null) { $idle = RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "MaxIdleTime" }
    Log "MaxIdleTime : $idle ms (1 ~ 1800000 이어야 됨, 0 은 제한 없음)"
    if ($idle -gt 0 -and $idle -le 1800000) { Result "양호" } else { Result "취약" }
}

Title "W-37" "예약 작업 점검"
# \Microsoft\ 아래는 윈도우 기본 작업이라 빼고 나머지만 보여줌
$tasks = @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" })
Log "기본 작업 말고 $($tasks.Count) 개"
foreach ($t in $tasks) {
    $act = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join "; "
    Log "$($t.TaskPath)$($t.TaskName) [$($t.State)] -> $act"
}
Result "인터뷰"


Write-Result ""
Write-Result "===================== 3. 패치 관리 ====================="

Title "W-38" "주기적 보안 패치 및 벤더 권고사항 적용"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 | ForEach-Object { Log "$($_.HotFixID) $($_.Description) $(if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') })" }
$wsus = RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "WUServer"
if ($wsus) { Log "WSUS 서버 : $wsus" }
if ($days -eq $null -or $days -gt 90) {
    Log "마지막 패치가 $days 일 전 (90일 넘게 패치 안함)"
    Result "취약"
} else {
    Log "패치 절차가 있는지 담당자 확인"
    Result "인터뷰"
}

Title "W-39" "백신 프로그램 업데이트"
$mp = $null
try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }
if (-not $mp) {
    Log "Windows Defender 정보 없음 (다른 백신 쓰는지 확인)"
    Result "인터뷰"
} else {
    Log "백신 엔진 업데이트 : $($mp.AntivirusSignatureLastUpdated) ($($mp.AntivirusSignatureAge) 일 전)"
    # 7일 안에 업데이트 했으면 양호로 봄
    if ($mp.AntivirusSignatureAge -le 7) { Result "양호" } else { Result "취약" }
}


Write-Result ""
Write-Result "===================== 4. 로그 관리 ====================="

Title "W-40" "정책에 따른 시스템 로깅 설정"
# 값 : 0 = 감사 안함, 1 = 성공, 2 = 실패, 3 = 성공+실패
# 가이드 권고 기준에 필요한 값이 들어있는지 비트로 봄 (예: 실패만 필요하면 2 나 3 이면 됨)
$audit = [ordered]@{
    "AuditAccountManage" = @("계정 관리", 2)
    "AuditAccountLogon" = @("계정 로그온 이벤트", 3)
    "AuditPrivilegeUse" = @("권한 사용", 3)
    "AuditDSAccess" = @("디렉터리 서비스 액세스", 2)
    "AuditLogonEvents" = @("로그온 이벤트", 3)
    "AuditPolicyChange" = @("정책 변경", 3)
}
$name = @{ 0 = "감사 안 함"; 1 = "성공"; 2 = "실패"; 3 = "성공/실패" }
$bad = @()
foreach ($k in $audit.Keys) {
    $v = SecVal $k
    if (-not $v) { $v = 0 }
    $need = $audit[$k][1]
    Log "$($audit[$k][0]) : $($name[[int]$v]) (권고 : $($name[$need]))"
    if (([int]$v -band $need) -ne $need) { $bad += $audit[$k][0] }
}
# "감사 정책 하위 범주 설정을 사용하여 감사 정책 범주 설정 재정의" 가 켜져있으면 위 값 대신 고급 감사 정책(auditpol)이 적용됨
$scen = RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy"
if ($bad.Count -eq 0) {
    Result "양호"
} elseif ($scen -eq 1) {
    Log "고급 감사 정책(auditpol) 사용중이라 위 값이 적용 안됨 -> auditpol /get /category:* 결과 확인"
    Result "인터뷰"
} else {
    Log "권고 기준 안맞는거 : $($bad -join ', ')"
    Result "취약"
}

Title "W-41" "NTP 및 시각 동기화 설정"
$src = (w32tm /query /source 2>$null | Out-String).Trim()
$w32 = SvcRunning "W32Time"
Log "시간 동기화 서버 : $src  (W32Time 실행 : $w32)"
if ($w32 -and $src -and $src -notlike "*CMOS*" -and $src -notlike "*Free-running*") {
    Result "양호"
} else {
    Result "취약"
}

Title "W-42" "이벤트 로그 관리 설정"
# 최대 로그 크기 10240KB(10485760 바이트) 이상
# (90일 이후 덮어쓰기 옵션은 2008 부터 없어져서 크기만 봄)
$bad = @()
foreach ($ln in "Application", "Security", "System") {
    $l = Get-WinEvent -ListLog $ln -ErrorAction SilentlyContinue
    Log "$ln : 최대 $([int]($l.MaximumSizeInBytes / 1KB)) KB, 모드 $($l.LogMode)"
    if ($l.MaximumSizeInBytes -lt 10485760) { $bad += $ln }
}
if ($bad.Count -eq 0) { Result "양호" } else { Result "취약" }

Title "W-43" "이벤트 로그 파일 접근 통제 설정"
# 예전 이벤트 로그 폴더(config) + 요즘 이벤트 로그 폴더(winevt\Logs) + LogFiles
$bad = @()
foreach ($d in "$env:windir\System32\config", "$env:windir\System32\winevt\Logs", "$env:windir\System32\LogFiles") {
    if (-not (Test-Path $d)) { continue }
    $ev = EveryoneAcl $d
    Log "$d Everyone : $(if ($ev) { $ev -join ', ' } else { '없음' })"
    if ($ev) { $bad += $d }
}
if ($bad.Count -eq 0) { Result "양호" } else { Result "취약" }


Write-Result ""
Write-Result "===================== 5. 보안 관리 ====================="

Title "W-44" "원격 레지스트리"
$rr = Get-Service RemoteRegistry -ErrorAction SilentlyContinue
Log "Remote Registry : $($rr.Status) (시작 유형 $($rr.StartType))"
if ($rr.Status -eq "Running") { Result "취약" } else { Result "양호" }

Title "W-45" "백신 프로그램 설치"
if ($mp) {
    Log "Windows Defender 사용 : $($mp.AntivirusEnabled), 실시간 감시 : $($mp.RealTimeProtectionEnabled)"
    if ($mp.AntivirusEnabled) { Result "양호" } else { Result "취약" }
} else {
    Log "Windows Defender 정보 없음 -> 다른 백신 설치됐는지 확인"
    Result "인터뷰"
}

Title "W-46" "SAM 파일 접근 통제 설정"
# Administrators(S-1-5-32-544), SYSTEM(S-1-5-18) 말고 다른 계정/그룹이 있으면 취약
$sam = "$env:windir\System32\config\SAM"
$bad = @()
$acl = Get-Acl $sam -ErrorAction SilentlyContinue
if ($acl) {
    foreach ($a in $acl.Access) {
        try { $sid = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $sid = "$($a.IdentityReference)" }
        Log "$($a.IdentityReference) : $($a.FileSystemRights)"
        if ($sid -ne "S-1-5-32-544" -and $sid -ne "S-1-5-18") { $bad += "$($a.IdentityReference)" }
    }
    if ($bad.Count -eq 0) { Result "양호" } else { Log "다른 계정/그룹 : $($bad -join ', ')"; Result "취약" }
} else {
    Log "SAM 파일 권한을 못 읽음"
    Result "인터뷰"
}

Title "W-47" "화면 보호기 설정"
# 정책(Policies)에 있으면 정책이 먼저 적용됨. 기준 : 사용, 암호 사용, 대기시간 10분(600초) 이하
# 사용자별 설정(HKCU)이라 이 스크립트를 돌린 계정 기준임
$pol = Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ErrorAction SilentlyContinue
$dsk = Get-ItemProperty "HKCU:\Control Panel\Desktop" -ErrorAction SilentlyContinue
$active = if ($pol.ScreenSaveActive) { $pol.ScreenSaveActive } else { $dsk.ScreenSaveActive }
$secure = if ($pol.ScreenSaverIsSecure) { $pol.ScreenSaverIsSecure } else { $dsk.ScreenSaverIsSecure }
$timeout = if ($pol.ScreenSaveTimeOut) { $pol.ScreenSaveTimeOut } else { $dsk.ScreenSaveTimeOut }
Log "계정 : $env:USERNAME  사용 : $active  암호 사용 : $secure  대기 시간 : $timeout 초"
if ($active -eq "1" -and $secure -eq "1" -and [int]$timeout -gt 0 -and [int]$timeout -le 600) {
    Result "양호"
} else {
    Result "취약"
}

Title "W-48" "로그온하지 않고 시스템 종료 허용"
$v = RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "shutdownwithoutlogon"
Log "shutdownwithoutlogon : $v (0 이 사용 안 함)"
if ($v -eq 0) { Result "양호" } else { Result "취약" }

Title "W-49" "원격 시스템에서 강제로 시스템 종료"
$list = SecVal "SeRemoteShutdownPrivilege"
$other = @()
foreach ($s in ($list -split ",")) {
    if (-not $s) { continue }
    $id = $s.Trim().TrimStart("*")
    Log "원격 시스템에서 강제 종료 : $(SidName $id)"
    if ($id -ne "S-1-5-32-544") { $other += (SidName $id) }
}
if ($other.Count -eq 0) { Result "양호" } else { Log "Administrators 말고 있는거 : $($other -join ', ')"; Result "취약" }

Title "W-50" "보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료"
$v = RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "CrashOnAuditFail"
Log "CrashOnAuditFail : $v (0 이 사용 안 함)"
if ($v -eq 0) { Result "양호" } else { Result "취약" }

Title "W-51" "SAM 계정과 공유의 익명 열거 허용 안 함"
$ra = RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
$rs = RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM"
Log "RestrictAnonymous : $ra  RestrictAnonymousSAM : $rs (둘 다 1 이어야 됨)"
if ($ra -eq 1 -and $rs -eq 1) { Result "양호" } else { Result "취약" }

Title "W-52" "Autologon 기능 제어"
$v = RegVal "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon"
Log "AutoAdminLogon : $v (없거나 0 이어야 됨)"
if ("$v" -eq "1") { Result "취약" } else { Result "양호" }

Title "W-53" "이동식 미디어 포맷 및 꺼내기 허용"
# AllocateDASD : 0 = Administrators, 1 = Administrators+Power Users, 2 = Administrators+Interactive Users, 없음 = 정의 안됨
$v = RegVal "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AllocateDASD"
Log "AllocateDASD : $v (0 이어야 됨, 빈칸은 정의 안됨)"
if ("$v" -eq "0") { Result "양호" } else { Result "취약" }

Title "W-54" "Dos 공격 방어 레지스트리 설정"
# 기준 : SynAttackProtect 1 이상, EnableDeadGWDetect 0, KeepAliveTime 300000, NoNameReleaseOnDemand 1
$tcp = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$syn = RegVal $tcp "SynAttackProtect"
$gw = RegVal $tcp "EnableDeadGWDetect"
$ka = RegVal $tcp "KeepAliveTime"
$nn = RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NoNameReleaseOnDemand"
if ($nn -eq $null) { $nn = RegVal $tcp "NoNameReleaseOnDemand" }
Log "SynAttackProtect : $syn  EnableDeadGWDetect : $gw  KeepAliveTime : $ka  NoNameReleaseOnDemand : $nn (빈칸은 설정 안됨)"
if ($syn -ge 1 -and $gw -eq 0 -and $gw -ne $null -and $ka -eq 300000 -and $nn -eq 1) { Result "양호" } else { Result "취약" }

Title "W-55" "사용자가 프린터 드라이버를 설치할 수 없게 함"
$v = RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers"
Log "AddPrinterDrivers : $v (1 이 사용)"
if ($v -eq 1) { Result "양호" } else { Result "취약" }

Title "W-56" "SMB 세션 중단 관리 설정"
# EnableForcedLogOff 1, AutoDisconnect 15분 이하. AutoDisconnect 가 없으면 윈도우 기본값 15분
$lan = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$fl = RegVal $lan "EnableForcedLogOff"
$ad = RegVal $lan "AutoDisconnect"
Log "EnableForcedLogOff : $fl  AutoDisconnect : $(if ($ad -eq $null) { '없음(기본 15)' } else { $ad }) 분"
if ($ad -eq $null) { $ad = 15 }
if ($fl -eq 1 -and $ad -le 15) { Result "양호" } else { Result "취약" }

Title "W-57" "로그온 시 경고 메시지 설정"
# 예전엔 -ne "" 로 비교해서 값이 아예 없으면($null) 양호로 나왔음 -> 공백만 있는것도 없는걸로 봄
# 빈 값처럼 보여도 NUL 문자(\0)가 들어있는 경우가 있어서 그것도 지우고 봄
$cap = ("" + (RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeCaption")) -replace "\x00", ""
$txt = ("" + (RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeText")) -replace "\x00", ""
Log "제목 : $cap"
Log "내용 : $txt"
if (-not [string]::IsNullOrWhiteSpace($cap) -and -not [string]::IsNullOrWhiteSpace($txt)) { Result "양호" } else { Result "취약" }

Title "W-58" "사용자별 홈 디렉터리 권한 설정"
# 진짜 사용자 프로필 폴더만 봄 (가이드에서 All Users, Default User 는 빼라고 함. Default, Public 도 사용자 홈이 아님)
$bad = @()
foreach ($p in (Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special })) {
    if (-not (Test-Path $p.LocalPath)) { continue }
    $ev = EveryoneAcl $p.LocalPath
    Log "$($p.LocalPath) Everyone : $(if ($ev) { $ev -join ', ' } else { '없음' })"
    if ($ev) { $bad += $p.LocalPath }
}
if ($bad.Count -eq 0) { Result "양호" } else { Result "취약" }

Title "W-59" "LAN Manager 인증 수준"
# 3 이상 = NTLMv2 응답만 보냄. 정책을 안 정했으면(값 없음) 2008 이후 윈도우 기본값이 3
$v = RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
if ($v -eq $null) {
    Log "LmCompatibilityLevel : 정책 정의 안됨 (윈도우 기본값 3 = NTLMv2 응답만 보냄)"
    $v = 3
} else {
    Log "LmCompatibilityLevel : $v (3 이상이어야 됨)"
}
if ($v -ge 3) { Result "양호" } else { Result "취약" }

Title "W-60" "보안 채널 데이터 디지털 암호화 또는 서명"
$net = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$r1 = RegVal $net "RequireSignOrSeal"
$r2 = RegVal $net "SealSecureChannel"
$r3 = RegVal $net "SignSecureChannel"
Log "RequireSignOrSeal : $r1  SealSecureChannel : $r2  SignSecureChannel : $r3 (셋 다 1 이어야 됨)"
if ($r1 -eq 1 -and $r2 -eq 1 -and $r3 -eq 1) { Result "양호" } else { Result "취약" }

Title "W-61" "파일 및 디렉토리 보호"
# C 드라이브만 보던거를 로컬 디스크 전부로 바꿈
$bad = @()
foreach ($d in (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3")) {
    Log "$($d.DeviceID) $($d.FileSystem)"
    if ($d.FileSystem -notin @("NTFS", "ReFS")) { $bad += $d.DeviceID }
}
if ($bad.Count -eq 0) { Result "양호" } else { Result "취약" }

Title "W-62" "시작 프로그램 목록 분석"
foreach ($k in "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") {
    $item = Get-Item $k -ErrorAction SilentlyContinue
    if ($item) {
        foreach ($n in $item.GetValueNames()) { Log "$k : $n = $($item.GetValue($n))" }
    }
}
foreach ($f in "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup") {
    Get-ChildItem $f -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "desktop.ini" } | ForEach-Object { Log "시작프로그램 폴더 : $($_.FullName)" }
}
Result "인터뷰"

Title "W-63" "도메인 컨트롤러-사용자의 시간 동기화"
# DomainRole 4, 5 가 도메인 컨트롤러
if ($cs.DomainRole -ge 4) {
    $skew = SecVal "MaxClockSkew"
    Log "컴퓨터 시계 동기화 최대 허용 오차 : $skew 분 (5 이하여야 됨)"
    if ($skew -and [int]$skew -le 5) { Result "양호" } else { Result "취약" }
} else {
    Log "도메인 컨트롤러 아님"
    Result "N/A"
}

Title "W-64" "윈도우 방화벽 설정"
$bad = @()
foreach ($fw in (Get-NetFirewallProfile)) {
    Log "$($fw.Name) 프로필 : $(if ($fw.Enabled) { '사용' } else { '사용 안 함' })"
    if (-not $fw.Enabled) { $bad += $fw.Name }
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
# 인터뷰, 취약 항목 번호 모으기
$code = ""
$askList = @()
$badList = @()
foreach ($l in $lines) {
    if ($l -match "^\[(W-\d+)\]") { $code = $Matches[1] }
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
