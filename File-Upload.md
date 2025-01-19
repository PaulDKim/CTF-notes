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
