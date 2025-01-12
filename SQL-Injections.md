# SQL Injections (SQLi) Notes

## Blind SQLi
Blind SQLi occurs when an application is vulnerable to SQL injection, but its HTTP responses do not contain the results 
of the relevant SQL query or the `specific` details of any database errors.  

In `blind sqli`, there are two main subdivisions:  
1. Boolean-Based Blind SQLi
2. Time-Based Blind SQLi

### Boolean-Based SQLi
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

If the application behaves differently in each case, it is susceptible to boolean-based blind SQL injections. However, there are cases when
injecting these kind of payloads won't trigger a difference in response from the web server (like the lab in Portswigger SQLi Practitioner Lab 10. 
