#!/bin/bash
# MySQL 취약점 점검 스크립트
# 주요정보통신기반시설 가이드 2026 (D-01 ~ D-26)
# 실행방법 : sudo bash mysql_check.sh  (DB 서버에서)
# 실행하면 mysql root 비밀번호 물어봄 (화면에 안 보임)
# 결과는 mysql_result_<서버IP>.txt 에 저장됨
# 점검만 하고 설정은 하나도 안 바꿈 (select, show 만 씀)
#
# 처음 버전에서 고친거
#  1. 비밀번호 칠때 화면에 보였음 -> read -s 로 안 보이게
#  2. mysql -p비밀번호 로 하면 점검하는 동안 ps 명령어로 다른 사람도 비밀번호를 볼수 있음
#     -> root 만 읽을수 있는 임시 설정파일(600)에 넣고 --defaults-file 로 접속, 끝나면 바로 지움
#  3. --defaults-file 로만 접속하니까 /root/.my.cnf 같은 다른 설정파일은 안 읽음
#     (예전엔 비밀번호를 틀려도 .my.cnf 에 있는 계정으로 접속돼서 점검이 되는 경우가 있었음)
#  4. 접속 안되면 바로 끝냄 (예전엔 접속 실패해도 결과가 전부 양호로 나왔음)
#  5. mysql.sys 같은 MySQL 내부 계정은 빼고 판단

if [ "$(id -u)" -ne 0 ]
then
    echo "root 로 실행하세요!! (sudo bash mysql_check.sh)"
    exit 1
fi

if ! command -v mysql > /dev/null
then
    echo "mysql 명령어가 없음 (DB 서버에서 실행해야 됨)"
    exit 1
fi

read -s -p "mysql root 비밀번호 입력 (화면에 안 보임) : " PW
echo ""

# 임시 접속 설정파일 만들기 (mktemp 는 이름 겹치지 않게 만들어주고 권한도 600 으로 만들어줌)
CNF=$(mktemp /tmp/.mysql_check_XXXXXX)
chmod 600 $CNF
# 스크립트가 어떻게 끝나든(Ctrl+C 포함) 임시파일 지우게 trap 걸어둠
# Ctrl+C 일때는 지우고 바로 끝내야돼서 exit 붙임
trap 'rm -f $CNF' EXIT
trap 'rm -f $CNF; exit 1' INT TERM
# 비밀번호에 " 나 \ 가 들어가도 되게 앞에 \ 붙여줌
PW_ESC=$(printf '%s' "$PW" | sed 's/\\/\\\\/g; s/"/\\"/g')
printf '[client]\nuser=root\npassword="%s"\n' "$PW_ESC" > $CNF
unset PW PW_ESC

# 쿼리 실행 (결과만, 제목줄 없이)
sql() {
    mysql --defaults-file=$CNF -N -B -e "$1" 2>/dev/null
}

# 쿼리 실행 (표 모양으로 결과파일에 남길때)
sqlt() {
    mysql --defaults-file=$CNF -t -e "$1" 2>/dev/null | sed 's/^/  /' >> $RESULT
}

# 접속 되는지 먼저 확인
if [ "$(sql 'select 1')" != "1" ]
then
    echo "mysql 접속 실패!! (비밀번호가 틀렸거나 mysql 이 꺼져있음)"
    exit 1
fi

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -z "$IP" ]
then
    IP=$(hostname)
fi
RESULT=mysql_result_$IP.txt
> $RESULT
chmod 600 $RESULT

title() {
    echo "" >> $RESULT
    echo "[$1] $2" >> $RESULT
}

log() {
    echo "$*" >> $RESULT
}

result() {
    echo "결과 : $1" >> $RESULT
}

# 권한이 기준을 넘는지 (0 이면 기준 이하)
perm_over() {
    echo $(( 0$1 & ~0$2 & 07777 ))
}

# MySQL 이 알아서 만드는 내부 계정 (잠겨있고 로그인 안됨) -> 판단할때 뺌
SYS="'mysql.sys','mysql.session','mysql.infoschema'"
# information_schema 에서 나오는 'user'@'host' 모양에서 root 랑 내부계정 빼기
not_admin() {
    grep -v "^'root'@" | grep -v "^'mysql\.\(sys\|session\|infoschema\)'@"
}

VER=$(sql "select version()")

echo "MySQL 취약점 점검 결과" >> $RESULT
echo "점검 날짜 : $(date '+%Y-%m-%d %H:%M:%S')" >> $RESULT
echo "호스트 이름 : $(hostname) ($IP)" >> $RESULT
echo "MySQL 버전 : $VER" >> $RESULT

echo "점검 시작!!"


echo "" >> $RESULT
echo "===================== 1. 계정 관리 =====================" >> $RESULT

title "D-01" "기본 계정의 비밀번호, 정책 등을 변경하여 사용"
# 1) 비밀번호가 비어있는 계정 (root 포함)
# 2) 이름이 없는 익명 계정 (user='') -> 아무 이름으로나 접속됨
# auth_socket 은 OS 계정으로 로그인하는 방식이라 비밀번호가 원래 없음 -> 뺌
EMPTY=$(sql "select concat(user,'@',host) from mysql.user where (authentication_string='' or authentication_string is null) and plugin not in ('auth_socket','unix_socket') and user not in ($SYS)")
ANON=$(sql "select concat('''''@',host) from mysql.user where user=''")
log "  비밀번호 없는 계정 : ${EMPTY:-없음}"
log "  익명 계정 : ${ANON:-없음}"
if [ -z "$EMPTY" ] && [ -z "$ANON" ]
then
    result 양호
else
    result 취약
fi

title "D-02" "데이터베이스의 불필요 계정을 제거하거나, 잠금설정 후 사용"
# 필요한 계정인지는 담당자가 알아야 돼서 목록 + 잠금여부 + 비밀번호 바꾼 날짜 보여줌
sqlt "select user, host, account_locked, password_last_changed from mysql.user where user not in ($SYS) order by user"
TEST=$(sql "select concat(user,'@',host) from mysql.user where user in ('','test','guest','demo') and account_locked='N'")
if [ -n "$TEST" ]
then
    log "  테스트/익명 계정 같은거 : $TEST"
    result 취약
else
    result 인터뷰
fi

title "D-03" "비밀번호 기간, 복잡도 설정"
# 가이드 예시 기준 : validate_password 컴포넌트 설치, policy MEDIUM 이상, 길이 8 이상,
#                   default_password_lifetime 90 (0 이면 무제한이라 안됨)
# 5.7 은 validate_password_length 처럼 _ 이고 8.0 은 validate_password.length 처럼 . 이라서 둘 다 되게
VP=$(sql "show variables like 'validate_password%'")
POLICY=$(echo "$VP" | awk '$1 ~ /[._]policy$/ {print $2}')
VLEN=$(echo "$VP" | awk '$1 ~ /[._]length$/ {print $2}')
MIXED=$(echo "$VP" | awk '$1 ~ /mixed_case_count$/ {print $2}')
NUM=$(echo "$VP" | awk '$1 ~ /number_count$/ {print $2}')
SPECIAL=$(echo "$VP" | awk '$1 ~ /special_char_count$/ {print $2}')
LIFE=$(sql "select @@default_password_lifetime")
log "  validate_password : policy=${POLICY:-없음} length=${VLEN:-없음} 대소문자=${MIXED:-없음} 숫자=${NUM:-없음} 특수문자=${SPECIAL:-없음}"
log "  default_password_lifetime : $LIFE (0 은 무제한)"
# 계정별로 따로 기간을 정해둔것도 보여줌 (ALTER USER ... PASSWORD EXPIRE INTERVAL)
sql "select concat(user,'@',host,' : ',password_lifetime,'일') from mysql.user where password_lifetime is not null and user not in ($SYS)" | sed 's/^/  계정별 설정 /' >> $RESULT
BAD=""
if [ -z "$VP" ]
then
    BAD="$BAD validate_password(미설치)"
else
    case "$POLICY" in
        MEDIUM|STRONG|1|2) ;;
        *) BAD="$BAD policy" ;;
    esac
    if [ -z "$VLEN" ] || [ "$VLEN" -lt 8 ]
    then
        BAD="$BAD length"
    fi
fi
if [ -z "$LIFE" ] || [ "$LIFE" -eq 0 ] || [ "$LIFE" -gt 90 ]
then
    BAD="$BAD default_password_lifetime"
fi
if [ -z "$BAD" ]
then
    result 양호
else
    log "  기준 안맞는거 :$BAD"
    result 취약
fi

title "D-04" "데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 대해서만 허용"
# 가이드에 나온 쿼리 그대로 SUPER 권한 있는 계정 찾고 root, 내부계정 뺌
sql "select grantee from information_schema.user_privileges where privilege_type='SUPER'" | sed 's/^/  SUPER 권한 : /' >> $RESULT
SUPERS=$(sql "select grantee from information_schema.user_privileges where privilege_type='SUPER'" | not_admin)
if [ -z "$SUPERS" ]
then
    log "  root 말고 관리자 권한 있는 계정 없음"
    result 양호
else
    log "  root 말고 SUPER 권한 있는 계정 : $(echo $SUPERS)"
    result 취약
fi

title "D-05" "비밀번호 재사용에 대한 제약 설정"
log "  가이드에 MySQL 점검 방법이 없음"
log "  (참고) password_history=$(sql 'select @@password_history')  password_reuse_interval=$(sql 'select @@password_reuse_interval')"
result N/A

title "D-06" "DB 사용자 계정을 개별적으로 부여하여 사용"
# 여러 사람이 계정 하나를 같이 쓰는지는 스크립트로 알 수 없어서 담당자 확인
log "  계정 목록 : $(sql "select concat(user,'@',host) from mysql.user where user not in ($SYS)" | tr '\n' ' ')"
result 인터뷰

title "D-07" "root 권한으로 서비스 구동 제한"
# 1) 실제로 돌고있는 mysqld 프로세스 계정 (/proc/PID 폴더 소유자)
# 2) 설정파일 [mysqld] 부분의 user= 값 ([client] 부분에도 user= 가 있어서 [mysqld] 만 봄)
PID=$(pgrep -x 'mysqld|mariadbd' | head -1)
CNF_USER=$(awk '/^[[:space:]]*\[/ {sec=$0} sec ~ /\[mysqld\]/ && /^[[:space:]]*user[[:space:]]*=/ {print FILENAME " : " $0}' /etc/my.cnf /etc/my.cnf.d/*.cnf /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/*.cnf 2>/dev/null)
log "  설정파일 user : ${CNF_USER:-설정 없음}"
if [ -n "$PID" ]
then
    RUN_USER=$(stat -c %U /proc/$PID)
    RUN_UID=$(stat -c %u /proc/$PID)
    log "  mysqld 실행 계정 : $RUN_USER (UID $RUN_UID, PID $PID)"
    if [ "$RUN_UID" -eq 0 ]
    then
        result 취약
    else
        result 양호
    fi
else
    log "  mysqld 프로세스를 못 찾음"
    result 인터뷰
fi

title "D-08" "안전한 암호화 알고리즘 사용"
# mysql_native_password 는 SHA-1 이라 약함. 8.0 기본은 caching_sha2_password (SHA-256)
sqlt "select user, host, plugin from mysql.user where user not in ($SYS)"
WEAK=$(sql "select concat(user,'@',host,'(',plugin,')') from mysql.user where plugin in ('mysql_native_password','mysql_old_password') and user not in ($SYS)")
if [ -z "$WEAK" ]
then
    log "  전부 SHA-256 이상 사용"
    result 양호
else
    log "  약한 방식 쓰는 계정 : $(echo $WEAK)"
    result 취약
fi

title "D-09" "일정 횟수의 로그인 실패 시 이에 대한 잠금정책 설정"
log "  가이드에 MySQL 점검 방법이 없음"
result N/A


echo "" >> $RESULT
echo "===================== 2. 접근 관리 =====================" >> $RESULT

title "D-10" "원격에서 DB 서버로의 접속 제한"
# host 가 % 나 빈칸이면 아무데서나 접속 가능
# skip_networking 이 ON 이면 원격접속 자체가 안됨
SKIPNET=$(sql "select @@skip_networking")
log "  bind_address : $(sql 'select @@bind_address')   skip_networking : $SKIPNET"
sqlt "select user, host from mysql.user where user not in ($SYS) order by user"
ANY=$(sql "select concat(user,'@',host) from mysql.user where (host='%' or host='') and user not in ($SYS)")
if [ "$SKIPNET" == "1" ]
then
    log "  원격 접속 꺼져있음"
    result 양호
elif [ -z "$ANY" ]
then
    log "  지정된 IP 에서만 접속 가능"
    result 양호
else
    log "  아무데서나 접속 가능한 계정 : $(echo $ANY)"
    result 취약
fi

title "D-11" "DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정"
# 일반 계정이 아래 중 하나라도 있으면 mysql 시스템 테이블(mysql.user 등)을 볼수 있음
#  1) 전체(*.*) 권한 (USAGE 는 접속만 되는 권한이라 뺌)
#  2) mysql DB 에 대한 권한
#  3) mysql DB 안 테이블에 대한 권한
GLOBAL=$(sql "select distinct grantee from information_schema.user_privileges where privilege_type <> 'USAGE'" | not_admin)
SCHEMA=$(sql "select distinct grantee from information_schema.schema_privileges where table_schema='mysql'" | not_admin)
TABLE=$(sql "select distinct grantee from information_schema.table_privileges where table_schema='mysql'" | not_admin)
log "  일반 계정 권한 : "
sql "select concat(grantee,' -> ',table_schema,' : ',group_concat(privilege_type)) from information_schema.schema_privileges group by grantee, table_schema" | not_admin | sed 's/^/    /' >> $RESULT
log "  전체(*.*) 권한 있는 일반 계정 : ${GLOBAL:-없음}"
log "  mysql DB 권한 있는 일반 계정 : $(echo ${SCHEMA:-없음} ${TABLE})"
if [ -z "$GLOBAL" ] && [ -z "$SCHEMA" ] && [ -z "$TABLE" ]
then
    result 양호
else
    result 취약
fi

title "D-12" "안전한 리스너 비밀번호 설정 및 사용"
log "  오라클 항목"
result N/A

title "D-13" "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브를 제거하여 사용"
log "  윈도우 ODBC 항목 (리눅스 MySQL 은 해당 없음)"
result N/A

title "D-14" "주요 설정파일 권한"
# 가이드 : my.cnf 는 600 또는 640 (/etc/my.cnf, 각 홈 디렉터리의 .my.cnf)
# /etc/my.cnf.d 안에 나눠서 넣은 설정파일도 같이 봄
CHK=0
FILES="/etc/my.cnf /etc/my.cnf.d/* /etc/mysql/my.cnf /etc/mysql/conf.d/* /etc/mysql/mysql.conf.d/*"
for h in $(awk -F: '($3 == 0 || $3 >= 1000) && $3 < 65534 {print $6}' /etc/passwd | sort -u)
do
    FILES="$FILES $h/.my.cnf"
done
for f in $FILES
do
    if [ -f "$f" ]
    then
        perm=$(stat -c %a "$f")
        log "  $f (소유자 $(stat -c %U "$f"), 권한 $perm)"
        if [ $(perm_over $perm 640) -ne 0 ]
        then
            CHK=1
        fi
    fi
done
if [ $CHK -eq 0 ]
then
    result 양호
else
    log "  640 넘는 파일 있음 (600 또는 640 이어야 됨)"
    result 취약
fi

title "D-15" "관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 제한"
log "  오라클 항목"
result N/A

title "D-16" "Windows 인증 모드 사용"
log "  MSSQL 항목"
result N/A


echo "" >> $RESULT
echo "===================== 3. 옵션 관리 =====================" >> $RESULT

title "D-17" "Audit Table은 데이터베이스 관리자 계정으로 접근하도록 제한"
log "  가이드에 MySQL 점검 방법이 없음"
result N/A

title "D-18" "응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정"
log "  가이드에 MySQL 점검 방법이 없음"
result N/A

title "D-19" "OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정"
log "  오라클 항목"
result N/A

title "D-20" "인가되지 않은 Object Owner의 제한"
log "  가이드에 MySQL 점검 방법이 없음"
result N/A

title "D-21" "인가되지 않은 GRANT OPTION 사용 제한"
# GRANT OPTION 있으면 자기 권한을 다른 계정한테 줄 수 있음
# 전체(*.*), DB, 테이블 단위 다 봄
sqlt "select user, host, grant_priv from mysql.user where user not in ($SYS)"
GRANTS=$(sql "select grantee from information_schema.user_privileges where is_grantable='YES' union select grantee from information_schema.schema_privileges where is_grantable='YES' union select grantee from information_schema.table_privileges where is_grantable='YES'" | not_admin | sort -u)
if [ -z "$GRANTS" ]
then
    log "  일반 계정에 GRANT OPTION 없음"
    result 양호
else
    log "  GRANT OPTION 있는 일반 계정 : $(echo $GRANTS)"
    result 취약
fi

title "D-22" "데이터베이스의 자원 제한 기능을 TRUE로 설정"
log "  오라클 항목"
result N/A

title "D-23" "xp_cmdshell 사용 제한"
log "  MSSQL 항목"
result N/A

title "D-24" "Registry Procedure 권한 제한"
log "  MSSQL 항목"
result N/A


echo "" >> $RESULT
echo "===================== 4. 패치 관리 =====================" >> $RESULT

title "D-25" "주기적 보안 패치 및 벤더 권고 사항 적용"
log "  현재 버전 : $VER"
log "  https://dev.mysql.com/downloads 최신 버전이랑 비교 필요"
result 인터뷰

title "D-26" "감사 기록 정책"
log "  가이드에 MySQL 점검 방법이 없음"
log "  (참고) general_log=$(sql 'select @@general_log')  log_error=$(sql 'select @@log_error')"
result N/A


GOOD=$(grep -c "^결과 : 양호" $RESULT)
BAD=$(grep -c "^결과 : 취약" $RESULT)
ASK=$(grep -c "^결과 : 인터뷰" $RESULT)
NA=$(grep -c "^결과 : N/A" $RESULT)
ASK_LIST=$(awk '/^\[D-/ {code=substr($1, 2, length($1)-2)} /^결과 : 인터뷰/ {printf "%s ", code}' $RESULT)
BAD_LIST=$(awk '/^\[D-/ {code=substr($1, 2, length($1)-2)} /^결과 : 취약/ {printf "%s ", code}' $RESULT)

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
echo "결과는 $RESULT 파일 보세요 (root 만 읽을수 있음 -> sudo cat 으로 보기)"
