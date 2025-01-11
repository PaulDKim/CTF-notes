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
