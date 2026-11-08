#!/bin/bash
# 톰캣 취약점 점검 스크립트
# 주요정보통신기반시설 가이드 2026 (WEB-01 ~ WEB-26)
# 실행방법 : sudo bash tomcat_check.sh [톰캣경로]
#   경로 안 쓰면 실행중인 톰캣 프로세스에서 찾고, 그래도 없으면 /opt/tomcat 으로 봄
# 결과는 tomcat_result_<서버IP>.txt 에 저장됨
# 점검만 하고 설정은 하나도 안 바꿈
#
# 처음 버전에서 고친거
#  1. web.xml, server.xml, tomcat-users.xml 에는 주석(<!-- -->) 안에 예시 설정이 엄청 많음
#     그냥 grep 하면 주석에 있는 CGIServlet, admin 계정 같은게 다 걸려서 틀리게 나왔음
#     -> 주석 지우고 보는 strip_xml 함수 만듦
#  2. <Connector ... /> 같은 태그가 여러 줄에 걸쳐 있어서 줄 단위 grep 이 잘 안됨
#     -> 태그 하나를 한 줄로 합쳐서 보는 tags 함수, 속성값 뽑는 attr 함수 만듦
#  3. 권한 비교를 [ -le ] 말고 비트로 (perm_over)
#  4. 톰캣 경로를 실행중인 프로세스에서 자동으로 찾음

if [ "$(id -u)" -ne 0 ]
then
    echo "root 로 실행하세요!! (sudo bash tomcat_check.sh)"
    exit 1
fi


#==========================================================
# 함수
#==========================================================

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

# 권한이 기준을 넘는지 (0 이면 기준 이하). 예) perm_over 640 600 -> 32
perm_over() {
    echo $(( 0$1 & ~0$2 & 07777 ))
}

# 파일 권한 확인. 기준 넘으면 1 리턴
# 톰캣은 root 로 돌리기도 하고 tomcat 계정으로 돌리기도 해서 소유자는 표시만 함
perm_check() {
    local perm=$(stat -c %a "$1")
    log "  $1 (소유자 $(stat -c %U "$1"), 권한 $perm)"
    if [ $(perm_over $perm $2) -ne 0 ]
    then
        return 1
    fi
    return 0
}

# XML 주석(<!-- ... -->) 지우고 보기
# 주석이 한 줄에 여러개 있거나 여러 줄에 걸쳐 있어도 됨
# (sed '/<!--/,/-->/d' 로 해봤는데 한 줄짜리 주석 뒤에 있는 진짜 설정까지 지워져서 awk 로 바꿈)
strip_xml() {
    awk '
    {
        line = $0
        out = ""
        while (line != "") {
            if (incomment) {
                p = index(line, "-->")
                if (p == 0) { line = "" }
                else { line = substr(line, p + 3); incomment = 0 }
            } else {
                p = index(line, "<!--")
                if (p == 0) { out = out line; line = "" }
                else { out = out substr(line, 1, p - 1); line = substr(line, p + 4); incomment = 1 }
            }
        }
        if (out ~ /[^[:space:]]/) print out
    }' "$1" 2>/dev/null
}

# 태그 하나를 한 줄로 합쳐서 보기
# 사용법 : tags 파일 태그이름    예) tags server.xml Connector
tags() {
    strip_xml "$1" | tr '\n\r\t' '   ' | sed 's/</\n</g' | grep "^<$2[[:space:]/>]"
}

# 태그 줄에서 속성값 뽑기    예) echo '<Connector port="8080" />' | attr port -> 8080
# 앞에 공백을 붙여서 찾는 이유 : port 로 찾으면 redirectPort 같은것도 걸릴수 있어서
attr() {
    grep -o "[[:space:]]$1=\"[^\"]*\"" | head -1 | cut -d'"' -f2
}

# web.xml 의 servlet-mapping 을 "서블릿이름 URL패턴..." 한 줄씩으로 뽑기
mappings() {
    strip_xml "$1" | tr '\n\r\t' '   ' | awk 'BEGIN { RS = "<servlet-mapping>" } NR > 1 {
        sub(/<\/servlet-mapping>.*/, "")
        gsub(/<\/?servlet-name>|<\/?url-pattern>/, " ")
        gsub(/[ ]+/, " ")
        sub(/^ /, "")
        print
    }'
}


#==========================================================
# 톰캣 경로 찾기
#==========================================================
TOMCAT=$1
if [ -z "$TOMCAT" ]
then
    # 실행중인 톰캣 프로세스에 -Dcatalina.base=경로 가 붙어있음
    TOMCAT=$(ps -eo args | grep "[o]rg.apache.catalina.startup.Bootstrap" | grep -o "\-Dcatalina.base=[^ ]*" | head -1 | cut -d= -f2)
fi
if [ -z "$TOMCAT" ]
then
    TOMCAT=/opt/tomcat
fi
if [ ! -f "$TOMCAT/conf/server.xml" ]
then
    echo "톰캣 경로를 못 찾았음 : $TOMCAT"
    echo "경로를 직접 써주세요  예) sudo bash tomcat_check.sh /opt/tomcat"
    exit 1
fi
CONF=$TOMCAT/conf
WEBAPPS=$TOMCAT/webapps
# 앱별 web.xml (ROOT, manager 같은거 안에 있는거)
APP_WEBXML=$(ls $WEBAPPS/*/WEB-INF/web.xml 2>/dev/null)
# 서비스용 앱 목록 (톰캣 깔때 같이 들어있는 docs, examples, manager, host-manager 는 뺌)
# 이 앱들 web.xml 에 있는 설정은 그 앱에만 적용돼서 서비스 앱 판정에 쓰면 틀림
APPS=""
for d in $WEBAPPS/*/
do
    a=$(basename "$d")
    case "$a" in
        docs|examples|manager|host-manager) ;;
        *) APPS="$APPS $a" ;;
    esac
done

# 스프링부트 앱 설정파일(application.properties, yml)에서 키 찾기. 주석 빼고 첫줄만
# 사용법 : app_prop 앱이름 찾을패턴
app_prop() {
    local files=$(ls $WEBAPPS/$1/WEB-INF/classes/application*.properties $WEBAPPS/$1/WEB-INF/classes/application*.yml $WEBAPPS/$1/WEB-INF/classes/application*.yaml 2>/dev/null)
    if [ -z "$files" ]
    then
        return
    fi
    grep -hiE "$2" $files | grep -v "^[[:space:]]*#" | head -1 | tr -d '\r'
}

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -z "$IP" ]
then
    IP=$(hostname)
fi
RESULT=tomcat_result_$IP.txt
> $RESULT
chmod 600 $RESULT

echo "톰캣 취약점 점검 결과" >> $RESULT
echo "점검 날짜 : $(date '+%Y-%m-%d %H:%M:%S')" >> $RESULT
echo "호스트 이름 : $(hostname) ($IP)" >> $RESULT
echo "톰캣 경로 : $TOMCAT" >> $RESULT

echo "점검 시작!! (톰캣 경로 : $TOMCAT)"


echo "" >> $RESULT
echo "===================== 1. 계정 관리 =====================" >> $RESULT

title "WEB-01" "Default 관리자 계정명 변경"
# 관리자 페이지 권한(manager-gui, manager-script, manager-jmx, manager-status, admin-gui...)이 있는 계정만 봄
# tomcat-users.xml 에 주석으로 된 예시 계정(admin, tomcat, role1...)이 있어서 주석은 빼고 봐야됨
ADMINS=$(tags $CONF/tomcat-users.xml user | grep -E 'roles="[^"]*(manager-|admin-)')
if [ -z "$ADMINS" ]
then
    log "  관리자 페이지 권한 있는 계정 없음 (관리자 페이지 안씀)"
    result 양호
else
    BAD=""
    while read line
    do
        name=$(echo "$line" | attr username)
        log "  관리자 계정 : $name (권한 : $(echo "$line" | attr roles))"
        if echo "$name" | grep -qiE "^(admin|administrator|manager|tomcat|root|test|both|role1|robot)$"
        then
            BAD="$BAD $name"
        fi
    done <<< "$ADMINS"
    if [ -z "$BAD" ]
    then
        result 양호
    else
        log "  기본/추측하기 쉬운 계정명 :$BAD"
        result 취약
    fi
fi

title "WEB-02" "취약한 비밀번호 사용 제한"
# 비밀번호는 결과파일에 안 남기고 길이랑 문자 종류만 봄
# 기준 : 영문/숫자/특수문자 3종류 8자리 이상 또는 2종류 10자리 이상, 계정명이랑 같으면 안됨
# server.xml Realm 에 CredentialHandler 가 있으면 비밀번호를 해시로 저장한거라 암호화된걸로 봄
if [ -z "$ADMINS" ]
then
    log "  관리자 계정 없음"
    result 양호
else
    HASH=$(tags $CONF/server.xml CredentialHandler | attr algorithm)
    if [ -n "$HASH" ]
    then
        log "  비밀번호 해시 사용중 (algorithm=$HASH)"
        result 양호
    else
        BAD=""
        while read line
        do
            name=$(echo "$line" | attr username)
            pw=$(echo "$line" | attr password)
            KIND=0
            echo "$pw" | grep -q '[a-zA-Z]' && KIND=$((KIND + 1))
            echo "$pw" | grep -q '[0-9]' && KIND=$((KIND + 1))
            echo "$pw" | grep -q '[^a-zA-Z0-9]' && KIND=$((KIND + 1))
            OK=0
            if [ $KIND -ge 3 ] && [ ${#pw} -ge 8 ]
            then
                OK=1
            elif [ $KIND -ge 2 ] && [ ${#pw} -ge 10 ]
            then
                OK=1
            fi
            if [ "$pw" == "$name" ] || echo "$pw" | grep -qiE "^(tomcat|admin|password|s3cret|changeit|changeme)"
            then
                OK=0
            fi
            if [ $OK -eq 1 ]
            then
                log "  $name : 길이 ${#pw}, 문자 종류 $KIND -> 통과"
            else
                log "  $name : 길이 ${#pw}, 문자 종류 $KIND -> 약함"
                BAD="$BAD $name"
            fi
        done <<< "$ADMINS"
        if [ -z "$BAD" ]
        then
            result 양호
        else
            result 취약
        fi
    fi
fi

title "WEB-03" "비밀번호 파일 권한 관리"
if perm_check $CONF/tomcat-users.xml 600
then
    result 양호
else
    result 취약
fi


echo "" >> $RESULT
echo "===================== 2. 서비스 관리 =====================" >> $RESULT

title "WEB-04" "웹 서비스 디렉터리 리스팅 방지 설정"
# DefaultServlet 의 listings 값. 안 적혀있으면 기본값 false
CHK=0
FOUND=0
for f in $CONF/web.xml $APP_WEBXML
do
    VAL=$(strip_xml $f | tr -d '\n\r' | grep -o "<param-name>[[:space:]]*listings[[:space:]]*</param-name>[[:space:]]*<param-value>[^<]*" | sed 's/.*<param-value>//' | tr -d ' ')
    if [ -n "$VAL" ]
    then
        FOUND=1
        log "  $f : listings = $(echo $VAL)"
        if echo "$VAL" | grep -qi true
        then
            CHK=1
        fi
    fi
done
if [ $FOUND -eq 0 ]
then
    log "  listings 설정 없음 (기본값 false)"
fi
if [ $CHK -eq 0 ]
then
    result 양호
else
    result 취약
fi

title "WEB-05" "지정하지 않은 CGI/ISAPI 실행 제한"
# 톰캣 기본 web.xml 에 CGIServlet 이 주석으로 들어가 있음. 주석 빼고 남아있으면 CGI 쓰는거
CHK=0
for f in $CONF/web.xml $APP_WEBXML
do
    if strip_xml $f | grep -q "CGIServlet"
    then
        log "  $f : CGIServlet 사용중"
        mappings $f | grep -iE "^cgi |/cgi-bin" | sed 's/^/    매핑 : /' >> $RESULT
        CHK=1
    fi
done
if [ $CHK -eq 0 ]
then
    log "  CGI 안씀 (주석 처리 상태)"
    result 양호
else
    result 취약
fi

title "WEB-06" "웹 서비스 상위 디렉터리 접근 제한 설정"
# Context 나 Resources 에 allowLinking="true" 가 있으면 링크 따라서 웹 경로 밖으로 나갈수 있음
LINKING=""
for f in $CONF/server.xml $CONF/context.xml $CONF/Catalina/*/*.xml $WEBAPPS/*/META-INF/context.xml
do
    if [ -f "$f" ] && tags "$f" Context | grep -q 'allowLinking="true"'
    then
        LINKING="$LINKING $f"
    fi
    if [ -f "$f" ] && tags "$f" Resources | grep -q 'allowLinking="true"'
    then
        LINKING="$LINKING $f"
    fi
done
if [ -z "$LINKING" ]
then
    log "  allowLinking 설정 없음"
    result 양호
else
    log "  allowLinking=true 있음 :$LINKING"
    result 취약
fi

title "WEB-07" "웹 서비스 경로 내 불필요한 파일 제거"
# 설치할때 같이 깔리는 예제, 매뉴얼, 관리자 페이지, 설명서 파일들
LEFT=""
for d in docs examples host-manager manager
do
    if [ -d $WEBAPPS/$d ]
    then
        LEFT="$LEFT webapps/$d"
    fi
done
for f in BUILDING.txt RELEASE-NOTES RELEASE-NOTES.txt RUNNING.txt CONTRIBUTING.md README.md
do
    if [ -f $TOMCAT/$f ]
    then
        LEFT="$LEFT $f"
    fi
done
log "  webapps 안 : $(ls $WEBAPPS | tr '\n' ' ')"
if [ -z "$LEFT" ]
then
    result 양호
else
    log "  남아있는 기본 파일 :$LEFT"
    result 취약
fi

title "WEB-08" "웹 서비스 파일 업로드 및 다운로드 용량 제한"
# 1) Connector 마다 maxPostSize 가 있는지 (-1 이면 제한 없음)
# 2) 업로드 크기 제한 : web.xml 의 multipart-config
#    스프링부트 앱은 application.properties 의 spring.servlet.multipart.max-file-size 로 함
#    conf/web.xml 에 있으면 전체 앱에 적용, 아니면 서비스 앱마다 따로 있어야 됨
# 둘 중 하나 되어있으면 양호
CHK=0
while read line
do
    if [ -z "$line" ]
    then
        continue
    fi
    port=$(echo "$line" | attr port)
    size=$(echo "$line" | attr maxPostSize)
    log "  Connector $port : maxPostSize = ${size:-설정 없음}"
    if [ -z "$size" ] || [ "$size" -lt 0 ]
    then
        CHK=1
    fi
done <<< "$(tags $CONF/server.xml Connector)"
UPLIMIT=0
if strip_xml $CONF/web.xml | grep -q "<max-file-size>"
then
    log "  conf/web.xml 에 multipart-config 있음 (전체 앱 적용)"
    UPLIMIT=1
elif [ -n "$APPS" ]
then
    UPLIMIT=1
    for a in $APPS
    do
        P=$(app_prop $a "max-file-size")
        if strip_xml $WEBAPPS/$a/WEB-INF/web.xml | grep -q "<max-file-size>"
        then
            log "  앱 $a : web.xml 에 multipart-config 있음"
        elif [ -n "$P" ]
        then
            log "  앱 $a : $(echo $P)"
        else
            log "  앱 $a : 업로드 크기 제한 없음"
            UPLIMIT=0
        fi
    done
fi
if [ $CHK -eq 0 ] || [ $UPLIMIT -eq 1 ]
then
    result 양호
else
    result 취약
fi

title "WEB-09" "웹 서비스 프로세스 권한 제한"
# ps | grep tomcat 하면 다른것도 걸려서 톰캣 메인 클래스 이름으로 찾음
# 실행 계정은 /proc/PID 폴더 소유자로 보는게 정확함 (ps 는 계정이름 길면 잘림)
PID=$(pgrep -f "org.apache.catalina.startup.Bootstrap" | head -1)
SVC_USER=$(systemctl show -p User --value tomcat 2>/dev/null)
log "  tomcat.service User : ${SVC_USER:-설정 없음(root)}"
if [ -n "$PID" ]
then
    TC_USER=$(stat -c %U /proc/$PID)
    TC_UID=$(stat -c %u /proc/$PID)
    log "  톰캣 실행 계정 : $TC_USER (UID $TC_UID, PID $PID)"
    if [ "$TC_UID" -eq 0 ]
    then
        result 취약
    else
        log "  실행 계정 쉘 : $(getent passwd $TC_USER | cut -d: -f7) (nologin 이 좋음)"
        result 양호
    fi
else
    log "  톰캣이 안 돌고 있어서 실행 계정 확인 못함"
    result 인터뷰
fi

title "WEB-10" "불필요한 프록시 설정 제한"
PROXY=$(tags $CONF/server.xml Connector | grep -E "proxyName=|proxyPort=")
if [ -z "$PROXY" ]
then
    log "  Connector 에 프록시 설정 없음"
    result 양호
else
    echo "$PROXY" | sed 's/^/  /' >> $RESULT
    log "  필요한 프록시인지 확인"
    result 인터뷰
fi

title "WEB-11" "웹 서비스 경로 설정"
# 웹 경로(appBase, docBase)가 톰캣 설치 폴더 안이나 시스템 폴더면 업무 영역이랑 분리가 안된걸로 봄
# 가이드 예시처럼 Context docBase 를 따로 빼놨으면 그걸로 판단
PATHS=""
while read line
do
    if [ -z "$line" ]
    then
        continue
    fi
    base=$(echo "$line" | attr appBase)
    case "$base" in
        /*) full=$base ;;
        *) full=$TOMCAT/$base ;;
    esac
    log "  Host $(echo "$line" | attr name) : appBase = $full"
    PATHS="$PATHS $full"
done <<< "$(tags $CONF/server.xml Host)"
DOCS=""
for f in $CONF/server.xml $CONF/Catalina/*/*.xml
do
    if [ -f "$f" ]
    then
        for d in $(tags "$f" Context | attr docBase)
        do
            log "  Context docBase : $d ($f)"
            DOCS="$DOCS $d"
        done
    fi
done
if [ -n "$DOCS" ]
then
    PATHS=$DOCS
fi
CHK=0
for p in $PATHS
do
    case "$p" in
        $TOMCAT|$TOMCAT/*|/|/etc*|/usr*|/bin*|/sbin*|/root*|/var/log*)
            log "  분리 안된 경로 : $p"
            CHK=1 ;;
    esac
done
if [ $CHK -eq 0 ]
then
    result 양호
else
    result 취약
fi

title "WEB-12" "웹 서비스 링크 사용 금지"
# -type l 이 심볼릭 링크
LINKS=$(find $WEBAPPS -type l 2>/dev/null)
if [ -z "$LINKS" ] && [ -z "$LINKING" ]
then
    log "  링크 없음, allowLinking 없음"
    result 양호
else
    echo "$LINKS" | grep . | head -20 | sed 's/^/  링크 : /' >> $RESULT
    if [ -n "$LINKING" ]
    then
        log "  allowLinking=true :$LINKING"
    fi
    result 취약
fi

title "WEB-13" "웹 서비스 설정 파일 노출 제한"
# DB 접속정보가 들어있는 파일은 600 이하여야 됨 (내용은 비밀번호라서 결과파일에 안 남김)
#  1) server.xml, context.xml 에 DB 연결(Resource password=) 설정이 있는 경우
#  2) 웹 앱 안의 설정파일 (application.properties, *.yml, META-INF/context.xml) 에 DB 정보가 있는 경우
#  3) WAR 파일 안에도 같은 설정파일이 들어있음
CHK=0
FOUND=0
for f in $CONF/server.xml $CONF/context.xml $CONF/Catalina/*/*.xml
do
    if [ -f "$f" ] && tags "$f" Resource | grep -q "password="
    then
        FOUND=1
        perm_check "$f" 600 || CHK=1
    fi
done
for f in $(find $WEBAPPS \( -path "*/WEB-INF/classes/*" -o -path "*/META-INF/*" \) -type f \( -name "*.properties" -o -name "*.yml" -o -name "*.yaml" -o -name "context.xml" \) 2>/dev/null)
do
    if grep -qiE "jdbc:|datasource|db\.password" "$f"
    then
        FOUND=1
        perm_check "$f" 600 || CHK=1
    fi
done
# zip(WAR) 파일 안의 파일 이름은 압축 안된 글자로 들어있어서 grep -a 로 찾을수 있음
for w in $(find $WEBAPPS -maxdepth 1 -name "*.war" 2>/dev/null)
do
    if grep -aqE "WEB-INF/classes/application[^/]*\.(properties|yml|yaml)" "$w"
    then
        FOUND=1
        log "  (WAR 안에 application 설정파일 있음)"
        perm_check "$w" 600 || CHK=1
    fi
done
if [ $FOUND -eq 0 ]
then
    log "  DB 연결 정보 있는 파일 못찾음"
fi
if [ $CHK -eq 0 ]
then
    result 양호
else
    result 취약
fi

title "WEB-14" "웹 서비스 경로 내 파일의 접근 통제"
# 가이드 조치가 chmod 750 이라서 conf, bin, lib, webapps 안에 다른사람(other) 권한이 있는 파일/폴더 찾음
# 상위 폴더가 750 이라 지금 당장은 못 들어가도, 폴더 권한 바뀌면 바로 열리니까 파일 권한도 봄
# -perm /007 = 다른사람 읽기/쓰기/실행 중 하나라도 있는거
OVER=$(find $CONF $TOMCAT/bin $TOMCAT/lib $WEBAPPS -perm /007 2>/dev/null)
log "  톰캣 폴더 : $(stat -c '%U %a' $TOMCAT)  conf : $(stat -c '%a' $CONF)  bin : $(stat -c '%a' $TOMCAT/bin)  webapps : $(stat -c '%a' $WEBAPPS)"
if [ -z "$OVER" ]
then
    log "  다른사람 권한 있는 파일 없음"
    result 양호
else
    log "  다른사람 권한 있는 파일/폴더 $(echo "$OVER" | wc -l) 개 (앞에 20개만)"
    for f in $(echo "$OVER" | head -20)
    do
        log "    $f ($(stat -c '%U %a' $f))"
    done
    result 취약
fi

title "WEB-15" "웹 서비스의 불필요한 스크립트 매핑 제거"
# 톰캣 기본 web.xml 에 있어야 되는 매핑은 default(/) 랑 jsp(*.jsp, *.jspx) 뿐임
# 그 외에 cgi, ssi 같은게 주석 풀려있으면 불필요한 매핑
mappings $CONF/web.xml | sed 's/^/  매핑 : /' >> $RESULT
EXTRA=$(mappings $CONF/web.xml | awk '$1 != "default" && $1 != "jsp" {print $1}' | tr '\n' ' ')
if [ -z "$EXTRA" ]
then
    log "  기본 매핑(default, jsp)만 있음"
    result 양호
else
    log "  기본 말고 있는 매핑 : $EXTRA"
    result 취약
fi

title "WEB-16" "웹 서비스 헤더 정보 노출 제한"
# 1) server.xml 에 ErrorReportValve showServerInfo="false" 있는지 (없으면 에러화면에 톰캣 버전 나옴)
# 2) 진짜로 없는 페이지 요청해서 에러화면이나 Server 헤더에 톰캣 정보가 나오는지 curl 로 확인
VALVE=$(tags $CONF/server.xml Valve | grep ErrorReportValve)
SHOWINFO=$(echo "$VALVE" | attr showServerInfo)
log "  ErrorReportValve showServerInfo : ${SHOWINFO:-설정 없음(기본 true)}"
SERVER_ATTR=$(tags $CONF/server.xml Connector | attr server)
if [ -n "$SERVER_ATTR" ]
then
    log "  Connector server 속성 : $SERVER_ATTR"
fi
LEAK=""
PORT=$(tags $CONF/server.xml Connector | grep -v "AJP" | head -1 | attr port)
if command -v curl > /dev/null && [ -n "$PORT" ]
then
    RESP=$(curl -s -i -m 5 "http://127.0.0.1:$PORT/no_such_page_check_$$" 2>/dev/null)
    LEAK=$(echo "$RESP" | grep -oE "Apache Tomcat/[0-9.]+|^Server: .*(Tomcat|Coyote).*" | head -1)
    log "  없는 페이지 요청 응답 : $(echo "$RESP" | head -1 | tr -d '\r')"
fi
if [ -n "$LEAK" ]
then
    log "  톰캣 정보 노출됨 : $LEAK"
    result 취약
elif [ "$SHOWINFO" == "false" ]
then
    result 양호
else
    result 취약
fi

title "WEB-17" "가상 디렉터리 삭제"
# server.xml 의 Context path 나 conf/Catalina/localhost/*.xml 파일이 가상 디렉터리
VDIR=$(tags $CONF/server.xml Context | grep "path=")
CTX_FILES=$(ls $CONF/Catalina/*/*.xml 2>/dev/null)
if [ -z "$VDIR" ] && [ -z "$CTX_FILES" ]
then
    log "  Context path 설정 없음"
    result 양호
else
    echo "$VDIR" | grep . | sed 's/^/  /' >> $RESULT
    echo "$CTX_FILES" | grep . | sed 's/^/  Context 파일 : /' >> $RESULT
    log "  필요한 가상 디렉터리인지 확인"
    result 인터뷰
fi

title "WEB-18" "웹 서비스 WebDAV 비활성화"
log "  가이드에 톰캣 점검 방법이 없음 (Nginx 만 나와있음)"
result N/A


echo "" >> $RESULT
echo "===================== 3. 보안 설정 =====================" >> $RESULT

title "WEB-19" "웹 서비스 SSI 사용 제한"
# CGI 랑 같이 기본 web.xml 에 주석으로 들어있음. 주석 빼고 SSIServlet 이나 SSIFilter 가 있으면 사용중
CHK=0
for f in $CONF/web.xml $APP_WEBXML
do
    if strip_xml $f | grep -qE "SSIServlet|SSIFilter"
    then
        log "  $f : SSI 사용중"
        CHK=1
    fi
done
if [ $CHK -eq 0 ]
then
    log "  SSI 안씀 (주석 처리 상태)"
    result 양호
else
    result 취약
fi

title "WEB-20" "SSL/TLS 활성화"
log "  가이드에 톰캣 점검 방법이 없음 (Nginx 만 나와있음)"
SSL=$(tags $CONF/server.xml Connector | grep -ciE 'SSLEnabled="true"')
log "  (참고) SSL Connector : $SSL 개"
result N/A

title "WEB-21" "HTTP 리디렉션"
log "  가이드에 톰캣 점검 방법이 없음 (Nginx 만 나와있음)"
result N/A

title "WEB-22" "에러 페이지 관리"
# 1) conf/web.xml 에 error-page 가 있으면 전체 앱에 적용
# 2) 아니면 서비스 앱마다 자기 web.xml 에 error-page 가 있어야 됨
# 3) 스프링부트 앱은 web.xml 없이 error.jsp 같은 에러 화면을 따로 쓰기도 함
#    근데 그건 앱 안에서 난 에러만 해당되고, 톰캣이 바로 내는 에러(잘못된 요청 400 등)는
#    톰캣 기본 화면이 나와서 이 경우는 담당자 확인(인터뷰)으로 함
if [ -n "$VALVE" ]
then
    log "  (참고) ErrorReportValve showReport=$(echo "$VALVE" | attr showReport) showServerInfo=$SHOWINFO"
fi
if strip_xml $CONF/web.xml | grep -q "<error-page>"
then
    log "  conf/web.xml 에 error-page 있음 (전체 앱 적용)"
    result 양호
else
    NONE=""
    VIEW=""
    for a in $APPS
    do
        if strip_xml $WEBAPPS/$a/WEB-INF/web.xml | grep -q "<error-page>"
        then
            log "  앱 $a : web.xml 에 error-page 있음"
            continue
        fi
        EV=$(ls -d $WEBAPPS/$a/WEB-INF/views/error.jsp $WEBAPPS/$a/WEB-INF/classes/templates/error.html $WEBAPPS/$a/WEB-INF/classes/templates/error $WEBAPPS/$a/WEB-INF/classes/static/error 2>/dev/null | head -1)
        if [ -n "$EV" ]
        then
            log "  앱 $a : web.xml error-page 는 없고 앱 에러 화면 있음 ($EV)"
            VIEW="$VIEW $a"
        else
            log "  앱 $a : 에러 페이지 설정 없음"
            NONE="$NONE $a"
        fi
    done
    if [ -z "$APPS" ] || [ -n "$NONE" ]
    then
        log "  conf/web.xml 에도 error-page 없음"
        result 취약
    elif [ -n "$VIEW" ]
    then
        log "  톰캣이 직접 내는 에러(400 등)는 톰캣 기본 화면이 나옴 -> 이대로 괜찮은지 확인"
        result 인터뷰
    else
        result 양호
    fi
fi

title "WEB-23" "LDAP 알고리즘 적절하게 구성"
# JNDIRealm(LDAP 연동)을 쓸때 digest 가 SHA-256 이상이어야 됨
LDAP=$(tags $CONF/server.xml Realm | grep JNDIRealm)
if [ -z "$LDAP" ]
then
    log "  LDAP 연동 안함"
    result N/A
else
    DIGEST=$(echo "$LDAP" | attr digest)
    if [ -z "$DIGEST" ]
    then
        DIGEST=$(tags $CONF/server.xml CredentialHandler | attr algorithm)
    fi
    log "  JNDIRealm digest : ${DIGEST:-없음}"
    if echo "$DIGEST" | grep -qiE "SHA-?(256|384|512)"
    then
        result 양호
    else
        result 취약
    fi
fi

title "WEB-24" "별도의 업로드 경로 사용 및 권한 설정"
# 스프링부트 앱 설정에 업로드 경로(이름에 upload 랑 dir/path/location 들어간 키)가 있으면 그 폴더를 직접 봄
#  - 웹 경로(webapps) 밖에 있어야 되고
#  - 다른사람 권한이 없어야 됨 (가이드 조치가 chmod 750)
# 설정에서 못 찾으면 이름에 upload 들어간 폴더만 찾아서 보여주고 담당자 확인
CHK=0
FOUND=0
MISSING=0
for a in $APPS
do
    line=$(app_prop $a "^[[:space:]]*[^=:#]*upload[^=:]*(dir|path|location)[^=:]*[=:]" | grep -v "spring.servlet.multipart")
    if [ -z "$line" ]
    then
        continue
    fi
    FOUND=1
    # "키=값" 이나 "키: 값" 에서 값만 (따옴표, 공백 빼고)
    d=$(echo "$line" | sed -E 's/^[^=:]*[=:][[:space:]]*//' | tr -d "\"' ")
    log "  앱 $a 업로드 경로 설정 : $d"
    if [ ! -d "$d" ]
    then
        log "    폴더가 없거나 상대경로라서 확인 못함"
        MISSING=1
        continue
    fi
    case "$d" in
        $WEBAPPS|$WEBAPPS/*)
            log "    웹 경로(webapps) 안에 있음"
            CHK=1 ;;
    esac
    perm_check "$d" 750 || CHK=1
done
if [ $FOUND -eq 0 ]
then
    UP=$(find $WEBAPPS $TOMCAT -maxdepth 3 -type d -iname "*upload*" 2>/dev/null | sort -u)
    for d in $UP
    do
        log "  업로드 폴더 후보 : $d ($(stat -c '%U %a' $d))"
    done
    log "  설정에서 업로드 경로를 못 찾음 -> 업로드 경로를 웹 경로 밖에 따로 쓰는지 담당자 확인"
    result 인터뷰
elif [ $CHK -eq 1 ]
then
    result 취약
elif [ $MISSING -eq 1 ]
then
    result 인터뷰
else
    result 양호
fi


echo "" >> $RESULT
echo "===================== 4. 패치 및 로그 관리 =====================" >> $RESULT

title "WEB-25" "주기적 보안 패치 및 벤더 권고사항 적용"
# version.sh 는 JAVA_HOME 이 없으면 안될때가 있어서 안되면 RELEASE-NOTES 에서 찾음
VER=$($TOMCAT/bin/version.sh 2>/dev/null | grep "Server version" | cut -d: -f2)
if [ -z "$VER" ]
then
    VER=$(grep -m1 -o "Apache Tomcat Version [0-9.]*" $TOMCAT/RELEASE-NOTES 2>/dev/null)
fi
log "  현재 버전 :${VER:- 확인 못함}"
log "  https://tomcat.apache.org 최신 버전이랑 비교 필요"
result 인터뷰

title "WEB-26" "로그 디렉터리 및 파일 권한 설정"
# 가이드 조치 : chmod o-rwx -> 다른사람 권한이 하나도 없어야 됨
# AccessLogValve 에 directory 를 따로 지정했으면 그 폴더도 봄
LOGDIR=$TOMCAT/logs
ALOG=$(tags $CONF/server.xml Valve | grep AccessLogValve | attr directory)
case "$ALOG" in
    "") ;;
    /*) LOGDIR="$LOGDIR $ALOG" ;;
    *) LOGDIR="$LOGDIR $TOMCAT/$ALOG" ;;
esac
LOGDIR=$(echo $LOGDIR | tr ' ' '\n' | sort -u | tr '\n' ' ')
OVER=$(find $LOGDIR -perm /007 2>/dev/null)
log "  로그 폴더 : $LOGDIR"
if [ -z "$OVER" ]
then
    log "  로그 폴더/파일에 다른사람 권한 없음"
    result 양호
else
    for f in $(echo "$OVER" | head -20)
    do
        log "  $f ($(stat -c '%U %a' $f))"
    done
    result 취약
fi


GOOD=$(grep -c "^결과 : 양호" $RESULT)
BAD=$(grep -c "^결과 : 취약" $RESULT)
ASK=$(grep -c "^결과 : 인터뷰" $RESULT)
NA=$(grep -c "^결과 : N/A" $RESULT)
ASK_LIST=$(awk '/^\[WEB-/ {code=substr($1, 2, length($1)-2)} /^결과 : 인터뷰/ {printf "%s ", code}' $RESULT)
BAD_LIST=$(awk '/^\[WEB-/ {code=substr($1, 2, length($1)-2)} /^결과 : 취약/ {printf "%s ", code}' $RESULT)

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
