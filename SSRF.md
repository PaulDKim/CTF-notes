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
 

