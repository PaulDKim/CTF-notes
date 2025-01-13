# SQL Injections (SQLi) Notes

## Blind SQLi
Blind SQLi occurs when an application is vulnerable to SQL injection, but its HTTP responses do not contain the results 
of the relevant SQL query or the `specific` details of any database errors.  

In `blind sqli`, there are two main subdivisions:  
1. Boolean-Based Blind SQLi
2. Time-Based Blind SQLi

### Conditional Responses: Boolean-Based Blind SQLi
This technique involves injecting SQL queries that produce different responses from the server based on whether a `condition` is `true` or `false`. 
The attacker infers information by observing variations in the applications `behavior`, such as differences in:  
* `Page content` : certain elements appearing or disappearing
* `Status codes` : 200 OK vs 500 Internal Server Error
* Redirects or other subtle indications

As an example, let's assume that the following query is meant to display the details of a product from the database.  
> SELECT * FROM products WHERE id = product_id

At first, a malicious hacker uses the application in a `legitimate way` to discover at least one exist product ID - in this example, 
it's product 42. Then they provide following two values for `product_id`:  
> 42 AND 1=1  
> 42 AND 1=0

If this query is executed in the application using simple string concatenation, the query becomes respectively:  
> SELECT * FROM products WHERE id = 42 AND 1=1
> SELECT * FROM products WHERE id = 42 AND 1=0

If the application behaves differently in each case, it is susceptible to boolean-based blind SQL injections. These type of `Boolean-Based Blind SQLi` attacks are useful for `conditional responses` (`portswigger sqli practitioner lab 09`) 

### Conditional Errors
However, there are cases when injecting these kind of payloads won't trigger a difference in response from the web server (like the lab in `Portswigger SQLi Practitioner Lab 10`).  

You may come across web applications that give you `conditional errors`, like `STATUS 500 Internal Server Error`. In cases like these I've learned two techniques:  
* You can utilize `||` concatenation and `CASE` statements to extract information. However, it's important to note that this works if there's no validation/sanization on the backend that checks for input length, as these payloads can get quite lengthy!
  * For example:
    * `...xyz' || (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END) ||'`
* You can also utilize `boolean payloads` as previously mentioned and combine them with `CASE` statements.
  * For example:
    * `...xyz' AND (SELECT CASE WHEN 1=1 THEN TO_CHAR(1/0) ELSE 'a' END) = 'a'-- -`
