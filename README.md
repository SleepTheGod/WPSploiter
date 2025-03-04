=== Fully Automated WordPress Vulnerability Scanner ===
Note: Use only on sites you own or have permission to test.
Enter the target WordPress URL (e.g., http://example.com): http://example.com
Enter authentication cookies (e.g., 'key=value; key2=value2') or press Enter to skip: 

[+] WordPress detected!

[*] Scanning target...
[+] WordPress Version: 5.7.1
[+] Detected plugin: wp-super-cache (Version: 1.6.8)
[+] Detected plugin: contact-form-7 (Version: 5.3.2)
[+] Detected theme: twentyfifteen (Version: 2.9)

[*] Testing WP Super Cache RCE...
[-] Skipping WP Super Cache RCE test: Plugin not found or no auth cookies.
[*] Testing Contact Form 7 File Upload...
[-] No file upload vulnerability detected.
[*] Testing XML-RPC DoS...
[!] Potentially vulnerable to XML-RPC DoS!
[*] Testing SQL Injection...
[-] No SQL Injection detected.
[*] Testing Generic XSS...
[-] No XSS detected.
[*] Testing Authentication Bypass...
[-] No auth bypass detected.

=== Scan Results ===
[!] Vulnerabilities Found:
 - Core - 5.7.1: CVE-2021-29447 - XML-RPC DoS [High]
 - Plugin - contact-form-7 5.3.2: CVE-2020-12345 - Unrestricted File Upload [Critical]
 - Plugin - wp-super-cache 1.6.8: CVE-2021-XYZ - Authenticated RCE via Cache Location [Critical]
 - Theme - twentyfifteen 2.9: CVE-2019-GHI - XSS in Theme Options [Medium]
