### What is `ffuf`?

**ffuf** is a fast web fuzzing tool that helps you discover hidden resources and vulnerabilities by sending a series of HTTP requests to a server. It can be used for:

- Discovering directories and files on a web server (directory fuzzing)
- Testing web application parameters (parameter fuzzing)
- Finding subdomains (subdomain fuzzing)
- Identifying specific values that are accepted in HTTP requests (value fuzzing)

---

### **Basic Syntax**
```bash
ffuf -w <wordlist> -u <url> [options]
```

Where:
- **`-w <wordlist>`**: Specifies the path to a wordlist (or list of fuzzing inputs) to test against the target.
- **`-u <url>`**: Specifies the URL to target, with a placeholder (usually `FUZZ`) for fuzzing.

### 1. **Directory Fuzzing**

Directory fuzzing allows you to discover hidden directories or files on a web server. For example, if you suspect that there are directories like `/admin`, `/private`, or `/images`, you can use `ffuf` to check for these directories.

**Example**:
```bash
ffuf -w /path/to/wordlist.txt -u http://example.com/FUZZ
```
> **`-u http://example.com/FUZZ`**: The `-u` flag specifies the URL to fuzz, with `FUZZ` being replaced by each word from the wordlist.

---

### 2. **Page Fuzzing**

Page fuzzing involves testing for specific pages on a website. It’s similar to directory fuzzing but focuses on specific filenames or endpoints.

**Example**:
```bash
ffuf -w /path/to/wordlist.txt -u http://example.com/FUZZ.html
```
> In this example, `FUZZ` is replaced with each word from the wordlist, and `.html` is appended to each one, testing for possible `.html` pages.

---

### 3. **Recursive Fuzzing**

Recursive fuzzing is useful when you want to follow links within the pages you discover and continue fuzzing the internal resources of the site.

**Example**:
```bash
ffuf -w /path/to/wordlist.txt -u http://example.com/FUZZ -recursion
```
> **`-recursion`**: Tells ffuf to follow links discovered within the pages, making it continue fuzzing deeper levels within the site.

---

### 4. **Subdomain Fuzzing**

Subdomain fuzzing involves discovering subdomains of a target domain. It can be useful for finding misconfigured or hidden subdomains like `admin.example.com`, `test.example.com`, etc.

**Example**:
```bash
ffuf -w /path/to/wordlist.txt -u http://FUZZ.example.com
```
> **`-u http://FUZZ.example.com`**: The `FUZZ` is replaced by each word from the wordlist, testing for possible subdomains of `example.com`.

---

### 5. **GET Parameter Fuzzing**

Fuzzing URL parameters in GET requests involves testing different values for parameters like `id`, `page`, `search`, etc., to see if there are hidden parameters or vulnerabilities like SQL injection or XSS.

**Example**:
```bash
ffuf -w /path/to/wordlist.txt -u http://example.com/page.php?param=FUZZ
```
> **`-u http://example.com/page.php?param=FUZZ`**: The `FUZZ` in the parameter will be replaced by each word from the wordlist, testing different values for `param`.

---

### 6. **POST Parameter Fuzzing**

POST parameter fuzzing is similar to GET parameter fuzzing but focuses on testing parameters in the request body. This is useful for testing web forms, APIs, or login pages.

**Example**:
```bash
ffuf -w /path/to/wordlist.txt -u http://example.com/login -X POST -d "username=admin&password=FUZZ"
```
> **`-X POST`**: Specifies the HTTP method as POST.
> **`-d "username=admin&password=FUZZ"`**: The `FUZZ` in the POST data will be replaced by each word from the wordlist, fuzzing the `password` parameter.

---

### 7. **Value Fuzzing**

Value fuzzing refers to testing different values in certain parameters, like headers, cookies, or specific HTTP request fields.

**Example**:
```bash
ffuf -w /path/to/wordlist.txt -u http://example.com/ -H "Authorization: Bearer FUZZ"
```
> **`-H "Authorization: Bearer FUZZ"`**: This tells ffuf to fuzz the value of the `Authorization` header by replacing `FUZZ` with each word in the wordlist.

---

### 8. **Filtering Results (`-fr` Flag)**

The `-fr` flag is used to filter out unwanted responses from the fuzzing results. You can use it to exclude results that contain certain strings (like errors or failed responses) so that you only see successful or relevant results.

**Example**:
```bash
ffuf -w /path/to/wordlist.txt -u http://example.com/FUZZ -fr "Failed to connect"
```
> **`-fr "Failed to connect"`**: This will filter out any responses containing the text "Failed to connect", so you only see the valid responses (like open directories or pages).

---

### 9. **Additional Useful Flags**

- **`-t <threads>`**: Specifies the number of threads to use for fuzzing (higher numbers mean faster but more resource-intensive).
  - Example: `-t 50` will run 50 threads at once.
- **`-s <status_code>`**: Filters results based on HTTP status codes.
  - Example: `-s 200` will only show responses with a status code of 200 (OK).
- **`-mc <match_code>`**: Specifies HTTP status codes to match in the response.
  - Example: `-mc 200` will only show responses with a status of 200 (OK).
- **`-v`**: Enables verbose output, providing more details during the fuzzing process.

---

### Full Example: Directory and Parameter Fuzzing

Here’s an example of a full fuzzing command that combines directory fuzzing and POST parameter fuzzing with result filtering:

```bash
ffuf -w /path/to/wordlist.txt -u http://example.com/FUZZ -X POST -d "username=admin&password=FUZZ" -fr "Failed to connect" -t 50
```

- **`-w /path/to/wordlist.txt`**: Wordlist to use for fuzzing.
- **`-u http://example.com/FUZZ`**: Fuzzing the URL for directories and parameters.
- **`-X POST`**: Making POST requests.
- **`-d "username=admin&password=FUZZ"`**: Fuzzing the password parameter in the POST request.
- **`-fr "Failed to connect"`**: Filtering out error responses that contain "Failed to connect."
- **`-t 50`**: Running the fuzzing with 50 threads.

---

### Conclusion

With this guide, you should be able to effectively use **ffuf** to fuzz a variety of web application components, including directories, pages, parameters (GET and POST), subdomains, and specific values. The key flags (`-u`, `-w`, `-fr`, etc.) allow for flexible and powerful web fuzzing, making **ffuf** a valuable tool for security testing.
