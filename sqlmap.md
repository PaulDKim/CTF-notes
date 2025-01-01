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
