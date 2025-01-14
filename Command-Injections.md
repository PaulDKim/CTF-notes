## Command Injection: Detection
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
