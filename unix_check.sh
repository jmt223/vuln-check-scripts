#!/bin/bash
# 리눅스 취약점 점검 스크립트
# 주요정보통신기반시설 가이드 2026 (U-01 ~ U-67)
# 실행방법 : sudo bash unix_check.sh
# 결과는 unix_result_<서버IP>.txt 에 저장됨 (서버 여러대 돌려도 파일 안 겹치게)
# 점검만 하고 설정은 하나도 안 바꿈
#
# 처음 버전에서 고친거
#  1. 결과 찍는 코드가 67번 똑같이 반복돼서 함수로 뺌 (title / log / result)
#  2. 권한을 [ $PERM -le 644 ] 로 비교했더니 606 같은것도 644 보다 작아서 양호로 나옴
#     -> 8진수 비트로 비교하는 perm_over 함수 만듦
#  3. ps -ef | grep 으로 서비스 찾으면 이름 비슷한 프로세스도 다 걸림
#     -> systemctl is-active 로 바꿈 (svc_on 함수)
#  4. 설정파일 볼때 주석(#)이랑 빈줄 빼고 보는 함수 만듦 (conf / getval)
#  5. sudo 로 돌리면 PATH 랑 umask 가 root 로 로그인했을때랑 달라서 su - 로 확인
#  6. 설정을 점검하는 항목인데 서비스를 아예 안쓰면 양호 말고 N/A 로 함

# root 인지 확인 (whoami 보다 id -u 가 확실하다고 함)
if [ "$(id -u)" -ne 0 ]
then
    echo "root 로 실행하세요!! (sudo bash unix_check.sh)"
    exit 1
fi

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -z "$IP" ]
then
    IP=$(hostname)
fi
RESULT=unix_result_$IP.txt

# 결과파일에 계정정보 같은게 들어가니까 root 만 볼수있게
> $RESULT
chmod 600 $RESULT


#==========================================================
# 함수
#==========================================================

# 항목 제목 찍기
title() {
    echo "" >> $RESULT
    echo "[$1] $2" >> $RESULT
}

# 결과파일에 내용 남기기
log() {
    echo "$*" >> $RESULT
}

# 판정 찍기 (양호 / 취약 / 인터뷰 / N/A)
result() {
    echo "결과 : $1" >> $RESULT
}

# 주석(#)이랑 빈 줄 빼고 파일 내용 보기 (파일 여러개 줘도 됨)
# 파일 이름이 하나도 안 들어오면 cat 이 키보드 입력을 기다리면서 멈춰서 그냥 끝냄
conf() {
    if [ $# -eq 0 ]
    then
        return
    fi
    cat "$@" 2>/dev/null | grep -v "^[[:space:]]*#" | grep -v "^[[:space:]]*$"
}

# 설정값 하나 뽑기. "KEY 값" 이나 "KEY = 값" 둘 다 됨. 같은게 여러번 있으면 마지막꺼가 적용됨
# 사용법 : getval 키 파일...
getval() {
    local key=$1
    shift
    conf "$@" | grep -i "^[[:space:]]*$key[[:space:]=]" | tail -1 | sed "s/^[[:space:]]*$key[[:space:]]*=*[[:space:]]*//I" | awk '{print $1}'
}

# 권한이 기준을 넘는지 계산. 0 이 나오면 기준 이하
# 기준에서 꺼져있는 비트가 켜져있으면 넘은거
# 예) perm_over 606 644 -> 2 (다른사람 쓰기 권한 때문에 넘음)
perm_over() {
    echo $(( 0$1 & ~0$2 & 07777 ))
}

# 파일 소유자, 권한 확인해서 결과파일에 남김. 문제 있으면 1 리턴
# 사용법 : file_check 파일 기준권한 "허용소유자들"  (소유자 안쓰면 root 만)
file_check() {
    local f=$1
    local max=$2
    local owners=${3:-root}
    if [ ! -e "$f" ]
    then
        return 0
    fi
    local perm=$(stat -c %a "$f")
    local owner=$(stat -c %U "$f")
    log "  $f (소유자 $owner, 권한 $perm)"
    if ! echo " $owners " | grep -q " $owner "
    then
        return 1
    fi
    if [ $(perm_over $perm $max) -ne 0 ]
    then
        return 1
    fi
    return 0
}

# 서비스가 켜져있는지 확인. 하나라도 켜져 있으면 0 리턴, 찾은 이름은 SVC_FOUND 에 넣음
# systemctl 로 서비스랑 소켓(.socket) 둘 다 보고, xinetd 로 도는거랑 그냥 떠있는 프로세스도 봄
svc_on() {
    local s
    SVC_FOUND=""
    for s in "$@"
    do
        if systemctl is-active --quiet "$s" 2>/dev/null || systemctl is-active --quiet "$s.socket" 2>/dev/null
        then
            SVC_FOUND=$s
            return 0
        fi
        if [ -f /etc/xinetd.d/$s ] && systemctl is-active --quiet xinetd 2>/dev/null
        then
            if conf /etc/xinetd.d/$s | grep -qiE "disable[[:space:]]*=[[:space:]]*no"
            then
                SVC_FOUND="$s(xinetd)"
                return 0
            fi
        fi
        # pgrep -x 는 프로세스 이름이 정확히 같은것만 찾음 (grep 처럼 비슷한 이름은 안걸림)
        if pgrep -x "$s" > /dev/null 2>&1
        then
            SVC_FOUND=$s
            return 0
        fi
    done
    return 1
}

# find 할때 -xdev 하면 / 파티션만 봐서 /home, /boot 처럼 따로 잡힌 파티션은 빠짐
# 그래서 로컬 디스크 파티션 목록을 먼저 뽑아놓고 거기서 다 찾음 (/proc 같은건 안들어감)
LOCAL_FS=$(findmnt -rn -t xfs,ext4,ext3,ext2,btrfs -o TARGET 2>/dev/null | tr '\n' ' ')
if [ -z "$LOCAL_FS" ]
then
    LOCAL_FS="/"
fi


echo "리눅스 취약점 점검 결과" >> $RESULT
echo "점검 날짜 : $(date '+%Y-%m-%d %H:%M:%S')" >> $RESULT
echo "호스트 이름 : $(hostname) ($IP)" >> $RESULT
echo "OS : $(cat /etc/redhat-release 2>/dev/null)" >> $RESULT

echo "점검 시작!! (파일 찾는 항목이 있어서 1~2분 걸림)"


echo "" >> $RESULT
echo "===================== 1. 계정관리 =====================" >> $RESULT

title "U-01" "root 계정 원격 접속 제한"
# 로키9는 /etc/ssh/sshd_config.d/ 안에 있는 설정이 sshd_config 보다 먼저 적용됨
# 그래서 sshd_config 만 grep 하면 틀릴수 있음 -> sshd -T 하면 실제로 적용된 값이 나옴
CHK=0
if svc_on sshd
then
    ROOTLOGIN=$(sshd -T 2>/dev/null | grep -i "^permitrootlogin" | awk '{print $2}')
    log "  ssh PermitRootLogin : $ROOTLOGIN (no 여야 됨)"
    if [ "$ROOTLOGIN" != "no" ]
    then
        CHK=1
    fi
else
    log "  ssh 안씀"
fi
# 텔넷은 /etc/securetty 에 pts 가 있으면 root 로 원격 접속이 됨
if svc_on telnet in.telnetd
then
    if [ ! -f /etc/securetty ] || grep -q "^pts" /etc/securetty
    then
        log "  telnet 으로 root 접속 가능"
        CHK=1
    fi
fi
if [ $CHK -eq 0 ]
then
    result 양호
else
    result 취약
fi

title "U-02" "비밀번호 관리정책 설정"
# 가이드 기준 : 최대 사용기간 90일 이하, 최소 사용기간 1일 이상, 최소 길이 8자 이상,
#              숫자/대문자/소문자/특수문자 1개 이상(credit -1), 최근 비밀번호 4개 이상 기억
# pwquality.conf.d 폴더 안에 따로 넣는 경우도 있어서 같이 봄
PWQ="/etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
MAX=$(getval PASS_MAX_DAYS /etc/login.defs)
MIN=$(getval PASS_MIN_DAYS /etc/login.defs)
LEN=$(getval minlen $PWQ)
DC=$(getval dcredit $PWQ)
UC=$(getval ucredit $PWQ)
LC=$(getval lcredit $PWQ)
OC=$(getval ocredit $PWQ)
# minlen 은 안 적혀있으면 기본값 8 (pwquality.conf 주석에 써있음)
if [ -z "$LEN" ]
then
    LEN=8
fi
# remember 는 pam 에 pam_pwhistory 가 들어가 있어야 적용됨
REMEMBER=""
if conf /etc/pam.d/system-auth | grep -q pam_pwhistory
then
    REMEMBER=$(conf /etc/pam.d/system-auth | grep pam_pwhistory | grep -o "remember=[0-9]*" | cut -d= -f2)
    if [ -z "$REMEMBER" ]
    then
        REMEMBER=$(getval remember /etc/security/pwhistory.conf)
    fi
    # 둘 다 없으면 기본값 10 (man pam_pwhistory)
    if [ -z "$REMEMBER" ]
    then
        REMEMBER=10
    fi
fi
log "  PASS_MAX_DAYS : ${MAX:-없음}   PASS_MIN_DAYS : ${MIN:-없음}   minlen : $LEN"
log "  dcredit : ${DC:-없음}  ucredit : ${UC:-없음}  lcredit : ${LC:-없음}  ocredit : ${OC:-없음}   remember : ${REMEMBER:-없음}"
BAD=""
if [ -z "$MAX" ] || [ "$MAX" -gt 90 ]
then
    BAD="$BAD PASS_MAX_DAYS"
fi
if [ -z "$MIN" ] || [ "$MIN" -lt 1 ]
then
    BAD="$BAD PASS_MIN_DAYS"
fi
if [ "$LEN" -lt 8 ]
then
    BAD="$BAD minlen"
fi
# credit 은 -1 이하여야 그 문자를 꼭 넣어야 됨 (0 이면 안 넣어도 통과됨)
for item in "dcredit:$DC" "ucredit:$UC" "lcredit:$LC" "ocredit:$OC"
do
    name=${item%%:*}
    val=${item#*:}
    if [ -z "$val" ] || [ "$val" -gt -1 ]
    then
        BAD="$BAD $name"
    fi
done
if [ -z "$REMEMBER" ] || [ "$REMEMBER" -lt 4 ]
then
    BAD="$BAD remember"
fi
if [ -z "$BAD" ]
then
    result 양호
else
    log "  기준 안맞는거 :$BAD"
    result 취약
fi

title "U-03" "계정 잠금 임계값 설정"
# 로키9는 pam_faillock 을 씀. pam 파일에 faillock 이 들어가 있어야 실제로 적용됨
# 잠금 횟수(deny)는 pam 줄에 직접 쓰거나 /etc/security/faillock.conf 에 씀
if conf /etc/pam.d/system-auth | grep -q pam_faillock
then
    DENY=$(conf /etc/pam.d/system-auth | grep pam_faillock | grep -o "deny=[0-9]*" | head -1 | cut -d= -f2)
    if [ -z "$DENY" ]
    then
        DENY=$(getval deny /etc/security/faillock.conf)
    fi
    # 아무데도 안 적혀있으면 기본값 3 (man faillock.conf)
    if [ -z "$DENY" ]
    then
        DENY=3
    fi
    log "  pam_faillock 적용됨, deny = $DENY (1~10 이어야 됨)"
    if [ $DENY -ge 1 ] && [ $DENY -le 10 ]
    then
        result 양호
    else
        result 취약
    fi
elif conf /etc/pam.d/system-auth | grep -q pam_tally2
then
    # 센토스7 같은 옛날꺼는 pam_tally2
    DENY=$(conf /etc/pam.d/system-auth | grep pam_tally2 | grep -o "deny=[0-9]*" | head -1 | cut -d= -f2)
    log "  pam_tally2 deny = ${DENY:-없음}"
    if [ -n "$DENY" ] && [ $DENY -ge 1 ] && [ $DENY -le 10 ]
    then
        result 양호
    else
        result 취약
    fi
else
    log "  pam 에 faillock 이 없음 (authselect enable-feature with-faillock 해야 적용됨)"
    result 취약
fi

title "U-04" "비밀번호 파일 보호"
# passwd 두번째 칸이 x 면 비밀번호는 shadow 파일에 들어있는거
NOT_X=$(awk -F: '$2 != "x" {print $1}' /etc/passwd)
if [ -f /etc/shadow ] && [ -z "$NOT_X" ]
then
    log "  shadow 파일 사용중"
    result 양호
else
    log "  두번째 칸이 x 가 아닌 계정 : $NOT_X"
    result 취약
fi

title "U-05" "root 이외의 UID가 0 금지"
# grep ":x:0:" 으로 하면 비밀번호 칸이 x 가 아닐때 못잡아서 awk 로 세번째 칸(UID)을 직접 봄
UID0=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
if [ -z "$UID0" ]
then
    log "  root 말고 UID 0 인 계정 없음"
    result 양호
else
    log "  UID 0 인 계정 : $UID0"
    result 취약
fi

title "U-06" "사용자 계정 su 기능 제한"
# 둘 중 하나면 양호
#  1) /etc/pam.d/su 에 pam_wheel.so 줄이 주석 없이 있음 (wheel 그룹만 su 가능)
#  2) su 명령어 그룹이 wheel 이고 권한이 4750 (다른사람 실행 X)
WHEEL=$(conf /etc/pam.d/su | grep -E "^auth[[:space:]]+required[[:space:]]+pam_wheel.so")
SU=$(command -v su)
SU_PERM=$(stat -c %a $SU)
SU_GRP=$(stat -c %G $SU)
log "  pam_wheel : ${WHEEL:-없음(주석처리)}"
log "  $SU 권한 : $SU_PERM, 그룹 : $SU_GRP"
if [ -n "$WHEEL" ]
then
    result 양호
elif [ "$SU_GRP" == "wheel" ] && [ $(perm_over $SU_PERM 4750) -eq 0 ]
then
    result 양호
else
    result 취약
fi

title "U-07" "불필요한 계정 제거"
# 필요한 계정인지는 담당자가 알아야 돼서 목록이랑 마지막 로그인만 보여줌
log "  로그인 가능한 계정 :"
for u in $(awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1}' /etc/passwd)
do
    LAST=$(lastlog -u $u 2>/dev/null | tail -1 | awk '{$1=""; print}')
    log "    $u (마지막 로그인 :$LAST)"
done
DEFAULT=$(grep -E "^(lp|uucp|nuucp|games|gopher|news|operator):" /etc/passwd | cut -d: -f1 | tr '\n' ' ')
log "  기본으로 깔리는 계정 중 남아있는거 : ${DEFAULT:-없음}"
result 인터뷰

title "U-08" "관리자 그룹에 최소한의 계정 포함"
grep "^root:" /etc/group >> $RESULT
# 네번째 칸이 그룹에 들어있는 계정들
MEMBER=$(awk -F: '$1 == "root" {print $4}' /etc/group)
if [ -z "$MEMBER" ]
then
    log "  root 그룹에 다른 계정 없음"
    result 양호
else
    log "  root 그룹에 있는 계정 : $MEMBER (필요한 계정인지 확인)"
    result 인터뷰
fi

title "U-09" "계정이 존재하지 않는 GID 금지"
# 1) 일반 그룹(GID 1000 이상) 중에 계정이 하나도 없는 그룹
#    (계정 기본그룹으로도 안쓰고, group 파일 네번째 칸에도 아무도 없는거)
# 2) passwd 에 적힌 GID 가 group 파일에 없는 계정
EMPTY=""
for g in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1 ":" $3 ":" $4}' /etc/group)
do
    gname=$(echo $g | cut -d: -f1)
    gid=$(echo $g | cut -d: -f2)
    members=$(echo $g | cut -d: -f3)
    used=$(awk -F: -v gid=$gid '$4 == gid' /etc/passwd | wc -l)
    if [ -z "$members" ] && [ $used -eq 0 ]
    then
        EMPTY="$EMPTY $gname($gid)"
    fi
done
NOGROUP=""
for gid in $(awk -F: '{print $4}' /etc/passwd | sort -u)
do
    if ! awk -F: -v gid=$gid '$3 == gid {found=1} END {exit !found}' /etc/group
    then
        NOGROUP="$NOGROUP $gid"
    fi
done
log "  계정 없는 일반 그룹 : ${EMPTY:-없음}"
log "  group 파일에 없는 GID : ${NOGROUP:-없음}"
if [ -z "$EMPTY" ] && [ -z "$NOGROUP" ]
then
    result 양호
else
    result 취약
fi

title "U-10" "동일한 UID 금지"
# uniq -d 는 중복된것만 보여줌
DUP=$(awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d)
if [ -z "$DUP" ]
then
    log "  중복 UID 없음"
    result 양호
else
    for id in $DUP
    do
        log "  UID $id : $(awk -F: -v id=$id '$3 == id {print $1}' /etc/passwd | tr '\n' ' ')"
    done
    result 취약
fi

title "U-11" "사용자 shell 점검"
# 가이드에 나온 로그인 필요없는 계정들이 nologin / false 인지
BAD=""
for u in daemon bin sys adm listen nobody nobody4 noaccess diag operator games gopher
do
    sh=$(awk -F: -v u=$u '$1 == u {print $7}' /etc/passwd)
    if [ -n "$sh" ]
    then
        log "  $u : $sh"
        case "$sh" in
            */nologin|*/false) ;;
            *) BAD="$BAD $u" ;;
        esac
    fi
done
if [ -z "$BAD" ]
then
    result 양호
else
    log "  로그인 쉘이 있는 계정 :$BAD"
    result 취약
fi

title "U-12" "세션 종료 시간 설정"
# /etc/profile 에만 넣는게 아니라 /etc/profile.d/ 에 따로 파일 만들어서 넣는 경우가 많아서 같이 봄
# 600초(10분) 이하여야 됨
TMOUT_VAL=$(conf /etc/profile /etc/bashrc /etc/profile.d/*.sh | grep -o "TMOUT=[0-9]*" | tail -1 | cut -d= -f2)
log "  TMOUT : ${TMOUT_VAL:-설정 없음}"
# csh 쓰는 경우는 autologout (분 단위)
AUTOLOGOUT=$(conf /etc/csh.cshrc /etc/csh.login | grep -o "autologout=[0-9]*" | tail -1 | cut -d= -f2)
if [ -n "$AUTOLOGOUT" ]
then
    log "  csh autologout : $AUTOLOGOUT"
fi
if [ -n "$TMOUT_VAL" ] && [ $TMOUT_VAL -gt 0 ] && [ $TMOUT_VAL -le 600 ]
then
    result 양호
else
    result 취약
fi

title "U-13" "안전한 비밀번호 암호화 알고리즘 사용"
# login.defs 설정 + 실제 shadow 파일에 저장된 비밀번호 형식도 봄
# $5$ = SHA-256, $6$ = SHA-512, $y$ = yescrypt. ! 나 * 는 잠긴 계정이라 뺌
METHOD=$(getval ENCRYPT_METHOD /etc/login.defs)
WEAK=$(awk -F: '$2 != "" && $2 !~ /^[!*]/ && $2 !~ /^\$(5|6|y|gy)\$/ {print $1}' /etc/shadow)
log "  ENCRYPT_METHOD : ${METHOD:-없음}"
log "  약한 방식으로 저장된 계정 : ${WEAK:-없음}"
if echo "$METHOD" | grep -qiE "^(SHA512|SHA256|YESCRYPT)$" && [ -z "$WEAK" ]
then
    result 양호
else
    result 취약
fi


echo "" >> $RESULT
echo "===================== 2. 파일 및 디렉토리 관리 =====================" >> $RESULT

title "U-14" "root 홈, 패스 디렉터리 권한 및 패스 설정"
# sudo 로 돌리면 PATH 가 sudo 설정(secure_path)으로 바뀌어버림
# root 가 실제로 로그인했을때 PATH 를 봐야돼서 su - root 로 확인
ROOT_PATH=$(su - root -c 'echo $PATH' 2>/dev/null | tail -1)
if [ -z "$ROOT_PATH" ]
then
    ROOT_PATH=$PATH
fi
log "  root PATH : $ROOT_PATH"
# . 이 맨 앞이나 중간에 있으면 안됨 (맨 끝은 괜찮음)
# :: 이나 맨앞 : 도 현재 폴더(.)랑 같은 뜻이라서 같이 봄
if echo "$ROOT_PATH" | grep -qE '^\.$|^\.:|:\.:|^:|::'
then
    result 취약
else
    result 양호
fi

title "U-15" "파일 및 디렉터리 소유자 설정"
# 소유자나 그룹이 없는 파일 (계정 지우고 파일만 남은거)
NOOWN=$(find $LOCAL_FS -xdev \( -nouser -o -nogroup \) 2>/dev/null)
if [ -z "$NOOWN" ]
then
    log "  소유자 없는 파일 없음"
    result 양호
else
    log "  소유자 없는 파일 $(echo "$NOOWN" | wc -l) 개 (앞에 20개만)"
    echo "$NOOWN" | head -20 | sed 's/^/    /' >> $RESULT
    result 취약
fi

title "U-16" "/etc/passwd 파일 소유자 및 권한 설정"
if file_check /etc/passwd 644
then
    result 양호
else
    result 취약
fi

title "U-17" "시스템 시작 스크립트 권한 설정"
# 시작 스크립트는 /etc/rc.d 아래랑 systemd 서비스 파일(/etc/systemd/system)
# 소유자가 root 가 아니거나 다른사람이 쓸 수 있으면 문제
BADF=$(find /etc/rc.d/ /etc/systemd/system/ -type f \( ! -user root -o -perm -o+w \) 2>/dev/null)
log "  점검한 파일 $(find /etc/rc.d/ /etc/systemd/system/ -type f 2>/dev/null | wc -l) 개"
if [ -z "$BADF" ]
then
    log "  전부 root 소유, 다른사람 쓰기 권한 없음"
    result 양호
else
    for f in $BADF
    do
        log "  $f ($(stat -c '%U %a' $f))"
    done
    result 취약
fi

title "U-18" "/etc/shadow 파일 소유자 및 권한 설정"
if file_check /etc/shadow 400
then
    result 양호
else
    result 취약
fi

title "U-19" "/etc/hosts 파일 소유자 및 권한 설정"
if file_check /etc/hosts 644
then
    result 양호
else
    result 취약
fi

title "U-20" "/etc/(x)inetd.conf 파일 소유자 및 권한 설정"
# 로키9는 inetd/xinetd 대신 systemd 를 씀
# 가이드에 systemd 는 /etc/systemd/system.conf 랑 /etc/systemd/ 안의 파일을 root, 600 으로 하라고 나와있음
CHK=0
for f in /etc/inetd.conf /etc/xinetd.conf /etc/xinetd.d/*
do
    if [ -f "$f" ]
    then
        file_check "$f" 600 || CHK=1
    fi
done
# -perm /177 은 600 에 없는 비트(실행, 그룹, 다른사람)가 하나라도 켜진 파일
OVER=$(find /etc/systemd -type f \( ! -user root -o -perm /177 \) 2>/dev/null)
if [ -n "$OVER" ]
then
    log "  /etc/systemd 아래 600 넘는 파일 $(echo "$OVER" | wc -l) 개"
    for f in $OVER
    do
        log "    $f ($(stat -c '%U %a' $f))"
    done
    CHK=1
fi
if [ $CHK -eq 0 ]
then
    result 양호
else
    result 취약
fi

title "U-21" "/etc/(r)syslog.conf 파일 소유자 및 권한 설정"
# 소유자는 root, bin, sys 중 하나 / 640 이하
CHK=0
FOUND=0
for f in /etc/rsyslog.conf /etc/syslog.conf
do
    if [ -f $f ]
    then
        FOUND=1
        file_check $f 640 "root bin sys" || CHK=1
    fi
done
if [ $FOUND -eq 0 ]
then
    log "  syslog 설정 파일 없음"
    result N/A
elif [ $CHK -eq 0 ]
then
    result 양호
else
    result 취약
fi

title "U-22" "/etc/services 파일 소유자 및 권한 설정"
if file_check /etc/services 644 "root bin sys"
then
    result 양호
else
    result 취약
fi

title "U-23" "SUID, SGID, Sticky bit 설정 파일 점검"
# SUID(4000), SGID(2000) 걸린 파일 다 찾고, 가이드에 나온 주요 파일이 있는지 따로 표시
# 꼭 필요한건지는 담당자 확인
SUIDS=$(find $LOCAL_FS -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
log "  SUID/SGID 파일 $(echo "$SUIDS" | grep -c .) 개"
for f in $SUIDS
do
    log "    $(stat -c '%A %U %G' $f) $f"
done
DANGER=$(echo "$SUIDS" | grep -E "/(dump|restore|unix_chkpwd|at|lpq|lpq-lpd|lpr|lpr-lpd|lprm|lprm-lpd|newgrp|lpc|lpc-lpd|traceroute)$" | tr '\n' ' ')
log "  가이드에 나온 주요 파일 중 있는거 : ${DANGER:-없음}"
result 인터뷰

title "U-24" "사용자, 시스템 환경변수 파일 소유자 및 권한 설정"
# 가이드 기준 : 소유자가 root 나 그 계정이고, root 랑 소유자만 쓰기 가능 (그룹, 다른사람 쓰기 X)
ENVFILES=".profile .cshrc .login .kshrc .bash_profile .bashrc .bash_login .bash_logout .exrc .netrc"
CHK=0
CNT=0
# passwd 에서 "계정:홈디렉토리" 뽑아서 하나씩 봄 (root 랑 일반계정)
for line in $(awk -F: '($3 == 0 || $3 >= 1000) && $3 < 65534 {print $1 ":" $6}' /etc/passwd)
do
    u=${line%%:*}
    home=${line#*:}
    for e in $ENVFILES
    do
        f="$home/$e"
        if [ -f "$f" ]
        then
            CNT=$((CNT + 1))
            owner=$(stat -c %U "$f")
            perm=$(stat -c %a "$f")
            if [ "$owner" != "root" ] && [ "$owner" != "$u" ]
            then
                log "  소유자 이상함 : $f (소유자 $owner)"
                CHK=1
            fi
            # 022 = 그룹 쓰기(020) + 다른사람 쓰기(002)
            if [ $(( 0$perm & 022 )) -ne 0 ]
            then
                log "  다른사람도 쓸수있음 : $f (권한 $perm)"
                CHK=1
            fi
        fi
    done
done
log "  점검한 환경변수 파일 $CNT 개"
if [ $CHK -eq 0 ]
then
    result 양호
else
    result 취약
fi

title "U-25" "world writable 파일 점검"
# 아무나 쓸 수 있는 파일. 가이드에 "설정 이유를 알고 있으면 양호" 라고 돼있어서
# 있으면 담당자한테 물어봐야됨
WW=$(find $LOCAL_FS -xdev -type f -perm -0002 2>/dev/null)
if [ -z "$WW" ]
then
    log "  world writable 파일 없음"
    result 양호
else
    log "  world writable 파일 $(echo "$WW" | wc -l) 개 (앞에 30개만)"
    echo "$WW" | head -30 | sed 's/^/    /' >> $RESULT
    result 인터뷰
fi

title "U-26" "/dev에 존재하지 않는 device 파일 점검"
# /dev 에 일반 파일이 있으면 이상한거
# /dev/shm, /dev/mqueue 는 프로그램들이 쓰는 공유메모리라 뺌
DEVF=$(find /dev \( -path /dev/shm -o -path /dev/mqueue \) -prune -o -type f -print 2>/dev/null)
if [ -z "$DEVF" ]
then
    log "  /dev 안에 일반 파일 없음"
    result 양호
else
    echo "$DEVF" | sed 's/^/  /' >> $RESULT
    result 취약
fi

title "U-27" "\$HOME/.rhosts, hosts.equiv 사용 금지"
# 가이드 : r 계열 서비스(rlogin, rsh, rexec) 안쓰면 양호
# 쓰면 파일 소유자가 root 나 그 계정, 권한 600 이하, + 설정 없어야 됨
FILES=""
for line in $(awk -F: '{print $1 ":" $6}' /etc/passwd)
do
    if [ -f "${line#*:}/.rhosts" ]
    then
        FILES="$FILES ${line%%:*}:${line#*:}/.rhosts"
    fi
done
if [ -f /etc/hosts.equiv ]
then
    FILES="$FILES root:/etc/hosts.equiv"
fi
if svc_on rlogin rsh rexec
then
    log "  r 계열 서비스 실행중 : $SVC_FOUND"
    CHK=0
    for item in $FILES
    do
        u=${item%%:*}
        f=${item#*:}
        file_check $f 600 "root $u" || CHK=1
        if grep -q "+" $f
        then
            log "  + 설정 있음 : $f"
            CHK=1
        fi
    done
    if [ $CHK -eq 0 ]
    then
        result 양호
    else
        result 취약
    fi
else
    log "  r 계열 서비스 안씀"
    if [ -n "$FILES" ]
    then
        log "  (파일은 있음 :$FILES  -> 안쓰면 지우는게 좋음)"
    fi
    result 양호
fi

title "U-28" "접속 IP 및 포트 제한"
# 방화벽이 켜져있는지만 보면 안되고, 열어둔 서비스/포트에 접속 IP 제한이 있는지 봐야됨
# firewalld 에서 zone 에 source(허용 IP)를 안 넣고 서비스를 열면 아무데서나 접속 가능
if systemctl is-active --quiet firewalld
then
    OPEN=""
    for z in $(firewall-cmd --get-active-zones 2>/dev/null | grep -v "^[[:space:]]")
    do
        SRC=$(firewall-cmd --zone=$z --list-sources)
        # dhcpv6-client 는 IP 받아오는거라 뺌
        SVC=$(firewall-cmd --zone=$z --list-services | sed 's/dhcpv6-client//')
        PORT=$(firewall-cmd --zone=$z --list-ports)
        log "  zone $z : 서비스 [$(echo $SVC)] 포트 [$PORT] 허용IP [$SRC]"
        firewall-cmd --zone=$z --list-rich-rules | grep . | sed 's/^/    rich rule : /' >> $RESULT
        if [ -z "$SRC" ] && [ -n "$(echo $SVC $PORT)" ]
        then
            OPEN="$OPEN $(echo $SVC $PORT)"
        fi
    done
    if [ -z "$OPEN" ]
    then
        result 양호
    else
        log "  IP 제한 없이 열린거 :$OPEN"
        result 취약
    fi
else
    # firewalld 안쓰고 nftables / iptables 를 직접 쓸수도 있어서 출발지(saddr) 규칙 있는지 봄
    RULES=$(nft list ruleset 2>/dev/null | grep -c "saddr")
    log "  firewalld 꺼져있음, nftables 출발지 IP 규칙 $RULES 개"
    if [ "$RULES" -gt 0 ]
    then
        result 인터뷰
    else
        result 취약
    fi
fi

title "U-29" "hosts.lpd 파일 소유자 및 권한 설정"
if [ -f /etc/hosts.lpd ]
then
    if file_check /etc/hosts.lpd 600
    then
        result 양호
    else
        result 취약
    fi
else
    log "  hosts.lpd 파일 없음"
    result 양호
fi

title "U-30" "UMASK 설정 관리"
# 그냥 umask 치면 sudo 에서 물려받은 값이 나와서 의미가 없음
# 1) 설정파일(login.defs, /etc/profile, /etc/bashrc)에 적힌 값
# 2) 실제로 로그인했을때 값 (su -). umask 를 0000 으로 해놓고 su 하는 이유는
#    로그인할때 umask 를 정해주는 설정이 없으면 0000 이 그대로 나와서 티가 나게 하려고
CHK=0
VALUES=""
DEF=$(getval UMASK /etc/login.defs)
log "  login.defs UMASK : ${DEF:-없음}"
VALUES="$DEF"
for v in $(conf /etc/profile /etc/bashrc /etc/profile.d/*.sh | grep -oE "umask[[:space:]]+[0-7]+" | awk '{print $2}')
do
    log "  profile/bashrc 에 적힌 umask : $v"
    VALUES="$VALUES $v"
done
for u in root $(awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd)
do
    REAL=$( (umask 0000; su - $u -c umask) 2>/dev/null | tail -1)
    log "  $u 로그인했을때 umask : ${REAL:-확인못함}"
    VALUES="$VALUES $REAL"
done
# 022 이상 = 그룹 쓰기(020), 다른사람 쓰기(002) 비트가 둘 다 막혀있어야 됨
for v in $VALUES
do
    if [ $(( 0$v & 022 )) -ne $(( 022 )) ]
    then
        CHK=1
    fi
done
if [ -z "$VALUES" ]
then
    result 취약
elif [ $CHK -eq 0 ]
then
    result 양호
else
    result 취약
fi

title "U-31" "홈 디렉토리 소유자 및 권한 설정"
# 홈 디렉토리 소유자가 그 계정이고 다른사람 쓰기 권한이 없어야 됨
CHK=0
for line in $(awk -F: '($3 == 0 || $3 >= 1000) && $3 < 65534 {print $1 ":" $6}' /etc/passwd)
do
    u=${line%%:*}
    home=${line#*:}
    if [ -d "$home" ]
    then
        owner=$(stat -c %U "$home")
        perm=$(stat -c %a "$home")
        log "  $u : $home (소유자 $owner, 권한 $perm)"
        if [ "$owner" != "$u" ] || [ $(( 0$perm & 02 )) -ne 0 ]
        then
            CHK=1
        fi
    fi
done
if [ $CHK -eq 0 ]
then
    result 양호
else
    result 취약
fi

title "U-32" "홈 디렉토리로 지정한 디렉토리의 존재 관리"
# 로그인 되는 계정 중에 홈 디렉토리가 없거나 / 로 돼있는거 (root 는 / 아니라서 상관없음)
CHK=0
for line in $(awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1 ":" $6}' /etc/passwd)
do
    u=${line%%:*}
    home=${line#*:}
    if [ ! -d "$home" ] || [ "$home" == "/" ]
    then
        log "  $u : 홈 디렉토리 이상 ($home)"
        CHK=1
    fi
done
if [ $CHK -eq 0 ]
then
    log "  홈 디렉토리 없는 계정 없음"
    result 양호
else
    result 취약
fi

title "U-33" "숨김파일 찾기"
# 점(.)으로 시작하는게 숨김파일. .bashrc 같은 기본 파일은 빼고 보여줌
HIDDEN=$(find /home /root /tmp /var/tmp /dev/shm -name ".*" 2>/dev/null)
NORMAL='/\.(bashrc|bash_profile|bash_logout|bash_history|profile|cache|config|local|ssh|lesshst|viminfo|mozilla|ICE-unix|X11-unix|font-unix|XIM-unix|Test-unix|python_history|wget-hsts)$'
log "  숨김 파일/폴더 전체 $(echo "$HIDDEN" | grep -c .) 개"
log "  기본 파일 말고 확인해볼거 :"
echo "$HIDDEN" | grep -vE "$NORMAL" | grep . | head -30 | sed 's/^/    /' >> $RESULT
result 인터뷰


echo "" >> $RESULT
echo "===================== 3. 서비스 관리 =====================" >> $RESULT

title "U-34" "Finger 서비스 비활성화"
if svc_on finger fingerd in.fingerd
then
    log "  실행중 : $SVC_FOUND"
    result 취약
else
    log "  finger 서비스 없음"
    result 양호
fi

title "U-35" "공유 서비스에 대한 익명 접근 제한 설정"
# 익명 접근 되는 공유 서비스 : FTP(anonymous), NFS, 삼바(guest)
CHK=0
USED=0
if svc_on vsftpd
then
    USED=1
    ANON=$(getval anonymous_enable /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf)
    # vsftpd 는 안 적어두면 기본값이 YES 라고 함 (man vsftpd.conf)
    log "  vsftpd anonymous_enable : ${ANON:-없음(기본값 YES)}"
    if [ -z "$ANON" ] || echo "$ANON" | grep -qi "yes"
    then
        CHK=1
    fi
fi
if svc_on proftpd
then
    USED=1
    if conf /etc/proftpd.conf /etc/proftpd/proftpd.conf | grep -qi "<Anonymous"
    then
        log "  proftpd 에 Anonymous 설정 있음"
        CHK=1
    fi
fi
if svc_on smb
then
    USED=1
    GUEST=$(conf /etc/samba/smb.conf | grep -iE "guest ok[[:space:]]*=[[:space:]]*yes|public[[:space:]]*=[[:space:]]*yes")
    if [ -n "$GUEST" ]
    then
        log "  삼바 guest 허용 : $GUEST"
        CHK=1
    fi
fi
if [ -n "$(conf /etc/exports /etc/exports.d/*.exports)" ] && svc_on nfs-server
then
    USED=1
    if conf /etc/exports /etc/exports.d/*.exports | grep -qE "anonuid|all_squash"
    then
        log "  NFS 익명(anonuid/all_squash) 공유 있음"
        CHK=1
    fi
fi
if [ $USED -eq 0 ]
then
    log "  FTP, 삼바, NFS 공유 서비스 안씀"
fi
if [ $CHK -eq 0 ]
then
    result 양호
else
    result 취약
fi

title "U-36" "r 계열 서비스 비활성화"
if svc_on rlogin rsh rexec in.rlogind in.rshd in.rexecd
then
    log "  실행중 : $SVC_FOUND"
    result 취약
else
    log "  r 계열 서비스 없음"
    result 양호
fi

title "U-37" "crontab 설정파일 권한 설정 미흡"
# 가이드 : crontab, at 명령어는 root 소유 750 (일반사용자 실행 X, SUID 도 빼라고 돼있음)
#         cron, at 관련 파일은 root 소유 640 이하
CHK=0
for f in /usr/bin/crontab /usr/bin/at
do
    if [ -f $f ]
    then
        file_check $f 750 || CHK=1
    fi
done
for f in /etc/crontab /etc/cron.allow /etc/cron.deny /etc/cron.d/* /var/spool/cron/* /etc/at.allow /etc/at.deny /var/spool/at/*
do
    if [ -f "$f" ]
    then
        file_check "$f" 640 || CHK=1
    fi
done
if [ $CHK -eq 0 ]
then
    result 양호
else
    result 취약
fi

title "U-38" "DoS 공격에 취약한 서비스 비활성화"
# echo, discard, daytime, chargen. xinetd 에서는 이름 뒤에 -stream, -dgram 이 붙음
if svc_on echo-stream echo-dgram discard-stream discard-dgram daytime-stream daytime-dgram chargen-stream chargen-dgram
then
    log "  실행중 : $SVC_FOUND"
    result 취약
else
    log "  echo, discard, daytime, chargen 없음"
    result 양호
fi

title "U-39" "불필요한 NFS 서비스 비활성화"
if svc_on nfs-server nfsd rpc.mountd
then
    log "  실행중 : $SVC_FOUND (꼭 필요한건지 확인)"
    result 취약
else
    log "  NFS 서비스 없음"
    result 양호
fi

title "U-40" "NFS 접근 통제"
# 공유 설정이 아예 없으면 점검할게 없어서 N/A
EXPORTS=$(conf /etc/exports /etc/exports.d/*.exports)
if [ -z "$EXPORTS" ]
then
    log "  NFS 공유 설정 없음"
    result N/A
else
    echo "$EXPORTS" | sed 's/^/  /' >> $RESULT
    CHK=0
    file_check /etc/exports 644 || CHK=1
    # * 로 공유하거나 호스트를 아예 안 적으면 (공백 다음에 바로 괄호) 아무나 접속 가능
    if echo "$EXPORTS" | grep -qE '\*|[[:space:]]\(|^[^[:space:]]+$'
    then
        log "  접속 호스트 제한 없는 공유 있음"
        CHK=1
    fi
    if [ $CHK -eq 0 ]
    then
        result 양호
    else
        result 취약
    fi
fi

title "U-41" "불필요한 automountd 제거"
if svc_on autofs automount
then
    log "  실행중 : $SVC_FOUND"
    result 취약
else
    log "  autofs 없음"
    result 양호
fi

title "U-42" "불필요한 RPC 서비스 비활성화"
if svc_on rpcbind rpc.cmsd rpc.ttdbserverd sadmind rusersd walld sprayd rstatd rpc.nisd rexd rpc.pcnfsd rpc.statd rpc.ypupdated rpc.rquotad kcms_server cachefsd
then
    log "  실행중 : $SVC_FOUND"
    result 취약
else
    log "  RPC 서비스 없음"
    result 양호
fi

title "U-43" "NIS, NIS+ 점검"
if svc_on ypserv ypbind ypxfrd rpc.yppasswdd rpc.ypupdated
then
    log "  실행중 : $SVC_FOUND"
    result 취약
else
    log "  NIS 서비스 없음"
    result 양호
fi

title "U-44" "tftp, talk 서비스 비활성화"
if svc_on tftp in.tftpd talk ntalk
then
    log "  실행중 : $SVC_FOUND"
    result 취약
else
    log "  tftp, talk 없음"
    result 양호
fi

# 메일 서비스 (U-45 ~ U-48 에서 같이 씀)
MAIL=""
if svc_on sendmail
then
    MAIL=sendmail
elif svc_on postfix
then
    MAIL=postfix
elif svc_on exim
then
    MAIL=exim
fi

title "U-45" "메일 서비스 버전 점검"
if [ -z "$MAIL" ]
then
    log "  메일 서비스 안씀"
    result 양호
else
    if [ "$MAIL" == "sendmail" ]
    then
        log "  sendmail 버전 : $(sendmail -d0.1 -bt < /dev/null 2>/dev/null | grep -i version | head -1)"
    elif [ "$MAIL" == "postfix" ]
    then
        log "  postfix 버전 : $(postconf -h mail_version 2>/dev/null)"
    else
        log "  $MAIL 버전 : $(exim -bV 2>/dev/null | head -1)"
    fi
    log "  최신 버전인지 확인 필요"
    result 인터뷰
fi

title "U-46" "일반 사용자의 메일 서비스 실행 방지"
if [ -z "$MAIL" ]
then
    log "  메일 서비스 안씀"
    result N/A
elif [ "$MAIL" == "sendmail" ]
then
    # sendmail.cf 의 PrivacyOptions 에 restrictqrun 이 있어야 됨
    PRIV=$(conf /etc/mail/sendmail.cf | grep PrivacyOptions)
    log "  $PRIV"
    if echo "$PRIV" | grep -q restrictqrun
    then
        result 양호
    else
        result 취약
    fi
elif [ "$MAIL" == "postfix" ]
then
    # postsuper 를 다른사람이 실행 못하게 (o-x)
    if file_check /usr/sbin/postsuper 750 "root"
    then
        result 양호
    else
        result 취약
    fi
else
    if file_check /usr/sbin/exiqgrep 750 "root"
    then
        result 양호
    else
        result 취약
    fi
fi

title "U-47" "스팸 메일 릴레이 제한"
if [ -z "$MAIL" ]
then
    log "  메일 서비스 안씀"
    result N/A
else
    # 릴레이 허용 범위가 맞는지는 사람이 봐야돼서 설정만 보여줌
    if [ "$MAIL" == "sendmail" ]
    then
        conf /etc/mail/access | sed 's/^/  access : /' >> $RESULT
        conf /etc/mail/sendmail.mc | grep -i relay | sed 's/^/  /' >> $RESULT
    elif [ "$MAIL" == "postfix" ]
    then
        log "  mynetworks : $(postconf -h mynetworks 2>/dev/null)"
        log "  smtpd_relay_restrictions : $(postconf -h smtpd_relay_restrictions 2>/dev/null)"
    fi
    result 인터뷰
fi

title "U-48" "expn, vrfy 명령어 제한"
if [ -z "$MAIL" ]
then
    log "  메일 서비스 안씀"
    result N/A
elif [ "$MAIL" == "sendmail" ]
then
    PRIV=$(conf /etc/mail/sendmail.cf | grep PrivacyOptions)
    log "  $PRIV"
    # goaway 에 noexpn, novrfy 가 다 들어있음
    if echo "$PRIV" | grep -q goaway || ( echo "$PRIV" | grep -q noexpn && echo "$PRIV" | grep -q novrfy )
    then
        result 양호
    else
        result 취약
    fi
elif [ "$MAIL" == "postfix" ]
then
    # postfix 는 expn 이 원래 없고 vrfy 만 막으면 됨
    VRFY=$(postconf -h disable_vrfy_command 2>/dev/null)
    log "  disable_vrfy_command : $VRFY"
    if [ "$VRFY" == "yes" ]
    then
        result 양호
    else
        result 취약
    fi
else
    result 인터뷰
fi

# DNS (U-49 ~ U-51)
NAMED=0
if svc_on named named-chroot
then
    NAMED=1
fi
NAMED_CONF=$(conf /etc/named.conf)

title "U-49" "DNS 보안 버전 패치"
if [ $NAMED -eq 0 ]
then
    log "  DNS 서비스 안씀"
    result N/A
else
    log "  $(named -v 2>/dev/null)"
    log "  최신 버전인지 확인 필요"
    result 인터뷰
fi

title "U-50" "DNS Zone Transfer 설정"
if [ $NAMED -eq 0 ]
then
    log "  DNS 서비스 안씀"
    result N/A
else
    # allow-transfer 가 없으면 기본이 아무나 허용이라서 취약
    XFER=$(echo "$NAMED_CONF" | grep allow-transfer)
    log "  ${XFER:-allow-transfer 설정 없음}"
    if [ -n "$XFER" ] && ! echo "$XFER" | grep -q any
    then
        result 양호
    else
        result 취약
    fi
fi

title "U-51" "DNS 서비스의 취약한 동적 업데이트 설정 금지"
if [ $NAMED -eq 0 ]
then
    log "  DNS 서비스 안씀"
    result N/A
else
    UPD=$(echo "$NAMED_CONF" | grep allow-update)
    log "  ${UPD:-allow-update 설정 없음}"
    if echo "$UPD" | grep -q any
    then
        result 취약
    else
        result 양호
    fi
fi

title "U-52" "Telnet 서비스 비활성화"
if svc_on telnet in.telnetd
then
    log "  실행중 : $SVC_FOUND"
    result 취약
else
    log "  telnet 없음"
    result 양호
fi

# FTP (U-53 ~ U-57)
FTP=""
if svc_on vsftpd
then
    FTP=vsftpd
elif svc_on proftpd
then
    FTP=proftpd
elif svc_on pure-ftpd
then
    FTP=pure-ftpd
fi
VSCONF=$(ls /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf 2>/dev/null | head -1)

title "U-53" "FTP 서비스 정보 노출 제한"
if [ -z "$FTP" ]
then
    log "  FTP 서비스 안씀"
    result N/A
elif [ "$FTP" == "vsftpd" ]
then
    BANNER=$(getval ftpd_banner $VSCONF)
    log "  ftpd_banner : ${BANNER:-없음}"
    if [ -n "$BANNER" ]
    then
        result 양호
    else
        result 취약
    fi
elif [ "$FTP" == "proftpd" ]
then
    IDENT=$(getval ServerIdent /etc/proftpd.conf /etc/proftpd/proftpd.conf)
    log "  ServerIdent : ${IDENT:-없음}"
    if echo "$IDENT" | grep -qi off
    then
        result 양호
    else
        result 취약
    fi
else
    result 인터뷰
fi

title "U-54" "암호화되지 않는 FTP 서비스 비활성화"
if [ -z "$FTP" ]
then
    log "  FTP 서비스 안씀"
    result 양호
elif [ "$FTP" == "vsftpd" ] && getval ssl_enable $VSCONF | grep -qi yes
then
    log "  vsftpd ssl_enable=YES (FTPS 로 암호화 사용중)"
    result 양호
else
    log "  암호화 안된 FTP 사용중 : $FTP (SFTP 나 FTPS 로 바꿔야 됨)"
    result 취약
fi

title "U-55" "FTP 계정 shell 제한"
FTPSH=$(awk -F: '$1 == "ftp" {print $7}' /etc/passwd)
if [ -z "$FTPSH" ]
then
    log "  ftp 계정 없음"
    result 양호
else
    log "  ftp 쉘 : $FTPSH"
    case "$FTPSH" in
        */nologin|*/false) result 양호 ;;
        *) result 취약 ;;
    esac
fi

title "U-56" "FTP 서비스 접근 제어 설정"
if [ -z "$FTP" ]
then
    log "  FTP 서비스 안씀"
    result N/A
else
    # 특정 IP 만 접속되게 했는지 (tcp_wrappers, hosts.allow, 방화벽 rich rule 등) 사람이 봐야됨
    log "  tcp_wrappers : $(getval tcp_wrappers $VSCONF)"
    conf /etc/hosts.allow /etc/hosts.deny | sed 's/^/  /' >> $RESULT
    firewall-cmd --list-rich-rules 2>/dev/null | grep -i ftp | sed 's/^/  /' >> $RESULT
    result 인터뷰
fi

title "U-57" "Ftpusers 파일 설정"
if [ -z "$FTP" ]
then
    log "  FTP 서비스 안씀"
    result N/A
elif [ "$FTP" == "proftpd" ]
then
    ROOTLOGIN=$(getval RootLogin /etc/proftpd.conf /etc/proftpd/proftpd.conf)
    log "  RootLogin : ${ROOTLOGIN:-없음(기본 off)}"
    if echo "$ROOTLOGIN" | grep -qi on
    then
        result 취약
    else
        result 양호
    fi
else
    # ftpusers 에 root 가 있으면 root 로 FTP 접속이 막힘
    CHK=$(conf /etc/vsftpd/ftpusers /etc/ftpusers | grep -c "^root$")
    log "  ftpusers 에 root : $CHK 줄"
    if [ $CHK -gt 0 ]
    then
        result 양호
    else
        result 취약
    fi
fi

# SNMP (U-58 ~ U-61)
SNMP=0
if svc_on snmpd
then
    SNMP=1
fi
SNMPCONF=$(conf /etc/snmp/snmpd.conf)

title "U-58" "불필요한 SNMP 서비스 구동 점검"
if [ $SNMP -eq 1 ]
then
    log "  snmpd 실행중"
    result 취약
else
    log "  SNMP 사용 안함"
    result 양호
fi

title "U-59" "안전한 SNMP 버전 사용"
if [ $SNMP -eq 0 ]
then
    log "  SNMP 사용 안함"
    result N/A
else
    # community 로 설정하는건 v1, v2c. v3 는 rouser/rwuser + createUser
    V12=$(echo "$SNMPCONF" | grep -cE "^(rocommunity|rwcommunity|com2sec)")
    V3=$(echo "$SNMPCONF" | grep -cE "^(rouser|rwuser|createUser)")
    log "  v1/v2c 설정 $V12 줄, v3 설정 $V3 줄"
    if [ $V12 -eq 0 ] && [ $V3 -gt 0 ]
    then
        result 양호
    else
        result 취약
    fi
fi

title "U-60" "SNMP Community String 복잡성 설정"
if [ $SNMP -eq 0 ]
then
    log "  SNMP 사용 안함"
    result N/A
else
    # 가이드 기준 : public, private 아니고 (영문+숫자 10자리 이상) 또는 (영문+숫자+특수문자 8자리 이상)
    # 커뮤니티 이름은 비밀번호 같은거라 결과파일에는 앞 2글자만 남김
    CHK=0
    COMMS=$(echo "$SNMPCONF" | awk '$1 ~ /^(rocommunity|rwcommunity)$/ {print $2} $1 == "com2sec" {print $4}')
    for c in $COMMS
    do
        OK=0
        if echo "$c" | grep -q '[a-zA-Z]' && echo "$c" | grep -q '[0-9]'
        then
            if echo "$c" | grep -q '[^a-zA-Z0-9]' && [ ${#c} -ge 8 ]
            then
                OK=1
            elif [ ${#c} -ge 10 ]
            then
                OK=1
            fi
        fi
        if [ "$c" == "public" ] || [ "$c" == "private" ]
        then
            OK=0
        fi
        log "  community ${c:0:2}*** (길이 ${#c}) : $([ $OK -eq 1 ] && echo 통과 || echo 기준미달)"
        if [ $OK -eq 0 ]
        then
            CHK=1
        fi
    done
    if [ -z "$COMMS" ]
    then
        log "  community 설정 없음 (v3 만 사용)"
    fi
    if [ $CHK -eq 0 ]
    then
        result 양호
    else
        result 취약
    fi
fi

title "U-61" "SNMP Access Control 설정"
if [ $SNMP -eq 0 ]
then
    log "  SNMP 사용 안함"
    result N/A
else
    # com2sec 의 source 가 default 거나, rocommunity 뒤에 허용 IP 를 안 적으면 아무데서나 접근 가능
    OPEN=$(echo "$SNMPCONF" | awk '($1 == "com2sec" && $3 == "default") || ($1 ~ /^(rocommunity|rwcommunity)$/ && ($3 == "" || $3 == "default")) {print $1, $3}')
    if [ -z "$OPEN" ]
    then
        result 양호
    else
        log "  접근 제한 없는 설정 : $OPEN"
        result 취약
    fi
fi

title "U-62" "로그인 시 경고 메시지 설정"
# 서버(motd) + 쓰고 있는 서비스(ssh, telnet, ftp, 메일)에 다 경고 메시지가 있어야 됨
CHK=0
if [ -n "$(tr -d '[:space:]' < /etc/motd 2>/dev/null)" ]
then
    log "  /etc/motd : 있음"
else
    log "  /etc/motd : 비어있음"
    CHK=1
fi
if svc_on sshd
then
    BANNER=$(sshd -T 2>/dev/null | grep -i "^banner" | awk '{print $2}')
    log "  ssh Banner : $BANNER"
    if [ -z "$BANNER" ] || [ "$BANNER" == "none" ]
    then
        CHK=1
    fi
fi
if svc_on telnet in.telnetd
then
    if [ -z "$(tr -d '[:space:]' < /etc/issue.net 2>/dev/null)" ]
    then
        log "  telnet /etc/issue.net : 비어있음"
        CHK=1
    fi
fi
if [ "$FTP" == "vsftpd" ] && [ -z "$(getval ftpd_banner $VSCONF)" ]
then
    log "  vsftpd ftpd_banner : 없음"
    CHK=1
fi
if [ "$MAIL" == "postfix" ]
then
    log "  postfix smtpd_banner : $(postconf -h smtpd_banner 2>/dev/null)"
fi
if [ $CHK -eq 0 ]
then
    result 양호
else
    result 취약
fi

title "U-63" "sudo 명령어 접근 관리"
# 가이드 : /etc/sudoers 소유자 root, 640 이하. sudoers.d 안에 파일도 같이 봄
CHK=0
for f in /etc/sudoers /etc/sudoers.d/*
do
    if [ -f "$f" ]
    then
        file_check "$f" 640 || CHK=1
    fi
done
if [ $CHK -eq 0 ]
then
    result 양호
else
    result 취약
fi


echo "" >> $RESULT
echo "===================== 4. 패치 관리 =====================" >> $RESULT

title "U-64" "주기적 보안 패치 및 벤더 권고사항 적용"
# 인터넷 안되는 서버도 있어서 dnf check-update 는 안하고 현재 상태만 보여줌
log "  OS : $(cat /etc/redhat-release 2>/dev/null)"
log "  실행중인 커널 : $(uname -r)"
log "  설치된 커널 중 최신 : $(rpm -q kernel --last 2>/dev/null | head -1 | awk '{print $1}')"
log "  최근에 설치/업데이트한 패키지 :"
rpm -qa --last 2>/dev/null | head -5 | sed 's/^/    /' >> $RESULT
result 인터뷰


echo "" >> $RESULT
echo "===================== 5. 로그 관리 =====================" >> $RESULT

title "U-65" "NTP 및 시각 동기화 설정"
# chronyd(로키 기본) 이나 ntpd 가 돌고 있고 동기화 서버(server/pool)가 설정돼 있어야 됨
if systemctl is-active --quiet chronyd
then
    SRV=$(conf /etc/chrony.conf /etc/chrony.d/*.conf | grep -E "^(server|pool)")
    log "  chronyd 실행중"
elif systemctl is-active --quiet ntpd
then
    SRV=$(conf /etc/ntp.conf | grep -E "^(server|pool)")
    log "  ntpd 실행중"
else
    SRV=""
    log "  시간 동기화 서비스 안돌고 있음"
fi
if [ -n "$SRV" ]
then
    echo "$SRV" | sed 's/^/  /' >> $RESULT
    result 양호
else
    result 취약
fi

title "U-66" "정책에 따른 시스템 로깅 설정"
# rsyslog 가 돌고 있는지 + 가이드 예시에 나온 기본 로그(messages, secure 등)가 설정돼 있는지
# 우리 회사 정책에 맞는지는 담당자 확인 필요해서 인터뷰
RSYS=$(conf /etc/rsyslog.conf /etc/rsyslog.d/*.conf)
if ! systemctl is-active --quiet rsyslog
then
    log "  rsyslog 안돌고 있음"
    result 취약
else
    echo "$RSYS" | grep -E "/var/log|/dev/console|:omusrmsg:" | sed 's/^/  /' >> $RESULT
    MISS=""
    for want in /var/log/messages /var/log/secure /var/log/maillog /var/log/cron
    do
        if ! echo "$RSYS" | grep -q "$want"
        then
            MISS="$MISS $want"
        fi
    done
    if [ -n "$MISS" ]
    then
        log "  없는 기본 로그 :$MISS"
        result 취약
    else
        log "  기본 로그 설정 있음 -> 정책에 맞는지 확인"
        result 인터뷰
    fi
fi

title "U-67" "로그 디렉터리 소유자 및 권한 설정"
# 가이드 : /var/log 안의 로그 파일 소유자가 root 이고 644 이하
# -perm /133 은 644 에 없는 비트(소유자 실행, 그룹 쓰기/실행, 다른사람 쓰기/실행)가 하나라도 켜진거
OVER=$(find /var/log -type f \( ! -user root -o -perm /133 \) 2>/dev/null)
log "  점검한 로그 파일 $(find /var/log -type f 2>/dev/null | wc -l) 개"
if [ -z "$OVER" ]
then
    log "  전부 root 소유, 644 이하"
    result 양호
else
    log "  기준 넘는 파일 $(echo "$OVER" | wc -l) 개"
    for f in $OVER
    do
        log "    $f ($(stat -c '%U %a' $f))"
    done
    result 취약
fi


# 개수 세기
GOOD=$(grep -c "^결과 : 양호" $RESULT)
BAD=$(grep -c "^결과 : 취약" $RESULT)
ASK=$(grep -c "^결과 : 인터뷰" $RESULT)
NA=$(grep -c "^결과 : N/A" $RESULT)
# 인터뷰 항목 번호만 모아서 보여줌 (담당자한테 물어볼거)
ASK_LIST=$(awk '/^\[U-/ {code=substr($1, 2, length($1)-2)} /^결과 : 인터뷰/ {printf "%s ", code}' $RESULT)
BAD_LIST=$(awk '/^\[U-/ {code=substr($1, 2, length($1)-2)} /^결과 : 취약/ {printf "%s ", code}' $RESULT)

echo "" >> $RESULT
echo "======================================" >> $RESULT
echo "양호 : $GOOD" >> $RESULT
echo "취약 : $BAD" >> $RESULT
echo "인터뷰 : $ASK" >> $RESULT
echo "N/A : $NA" >> $RESULT
echo "취약 항목 : $BAD_LIST" >> $RESULT
echo "인터뷰 항목 : $ASK_LIST" >> $RESULT

echo "점검 끝!!"
echo "양호 : $GOOD   취약 : $BAD   인터뷰 : $ASK   N/A : $NA"
echo "결과는 $RESULT 파일 보세요"
