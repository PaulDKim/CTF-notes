## Detection
To inject an additional command to the intended one, we may use any of the following operators:

| Injection Operator | Injection Character | URL-Encoded Character | Executed Command                                    |
|--------------------|---------------------|-----------------------|-----------------------------------------------------|
| Semicolon          | ;                   | %3b                   | Both                                                |
| New Line           | \n                  | %0a                   | Both                                                |
| Background         | &                   | %26                   | Both (second output generally shown first)          |
| Pipe               | \|                   | %7c                   | Both (only second output is shown)                  |
| AND                | &&                  | %26%26                | Both (only if first succeeds)                       |
| OR                 | \|\|                  | %7c%7c                | Second (only if first fails)                        |
| Sub-Shell          | ``                  | %60%60                | Both (Linux-only)                                   |
| Sub-Shell          | $( )                | %24%28%29             | Both (Linux-only)                                   |


We can use any of these operators to inject another command so both or either of the commands get executed. We would write our expected input (e.g., an IP), then use any of the above operators, and then write our new command.

> Tip: In addition to the above, there are a few unix-only operators, that would work on Linux and macOS, but would not work on Windows, such as wrapping our injected command with double backticks (``) or with a sub-shell operator ($()).

In general, for basic command injection, `all` of these operators can be used for command injections `regardless of the web application language, framework, or back-end server.` For example, if we are injecting in a `PHP` web application running on a Linux server, or a `.Net` web application running on a `Windows` back-end server, or a `NodeJS` web application running on a `macOS` back-end server, the listed injections should work regardless. 
> Note: The only exception may be the `;` semi-colon, which will not work if the command was being executed with `Windows Command Line (CMD)`, but would still work if it was being executed with `Windows PowerShell`. 

## Injecting Commands

Lets say we come across a web application that allows the user to input a valid IP address so that the web application can check if the IP address is "active". When a malicious actor uses one of the above `injection operators` like `;`, the web application may request that the user inputs a valid formatted string, or IP address in this case. If you append `;whoami` to a valid IP address, the web application could still give you an error stating to match the requested format. 
> TIP: it's important to check if the web application is sending the `payload` to the backend. You can check this by going to the browser's `developer tools` -> `network` and resend the payload like `127.0.0.1;whoami` again. If there are no network requests made when you clicked on the `submit` or `check` button, and still got an error message... this indicates the `user input validation is happening on the front-end`

> Interesting Note: It's very common for developers only to perform input validation on the front-end while not validating or santizing the input on the back-end.

### Bypassing Front-End Validation 

`Frontend validation checks` typically ensures that the user input matches a certain expected format before being sent to the backend, such as checking for a `valid IP address` or `rejecting special characters`. However, this `validation is usually only applied in the browser`. 
> You can use a web proxy like `Burp Suite` to intercept the HTTP request before it reaches the backend.

Since `frontend validation` happens on the client side (`in the browser`), it can be bypassed by `manually editing the request that is being sent to the server`. A malicous actor can modify the intercepted request to inject commands (`e.g. 127.0.0.1; whoami`), `URL-encode` the payload, and then the send it to the server directly. 
