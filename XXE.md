## What is XML?
`XML (extensible markup language)` is a language for storing and transporting data. It's similar to `HTML` in that it utilizes a tree-like structure with `tags`. However, XML
is different from HTML in that the `tags` are `undefined`. So it's useful to name tags that `describe` the `data`. 

## What are XML Entities? 
XML entities are special codes used to represent characters that might otherwise be misinterpreted in XML.  

#### **Common XML Entities:**  
| Entity | Character | Description |
|--------|----------|-------------|
| `&lt;`  | `<`  | Less than |
| `&gt;`  | `>`  | Greater than |
| `&amp;`  | `&`  | Ampersand |
| `&quot;`  | `"`  | Double quote |
| `&apos;`  | `'`  | Single quote |

### **Example:**  
```xml
<message>Use &lt;b&gt;bold&lt;/b&gt; for bold text.</message>
```
Displays as: 
```
Use <b>bold</b> for bold text.
```

### **Custom Entities:**  
You can define your own entities in a DTD (Document Type Definition):  
```xml
<!DOCTYPE note [
  <!ENTITY myName "John Doe">
]>
<note>
  <to>&myName;</to>
</note>
```
### What are Custom XML Entities? 
You can think of custom XML entities as variables you define within the `DTD (document type definition)`. Note that these cusotm XML entities can be either `internal` or `external`

#### External Entitities
XML external entities are a type of custom entity whose definition is located outside of the DTD where they are declared.
The declaration of an external entity uses the `SYSTEM` keyword and must specify a URL from which the value of the entity should be loaded. For example:

```xml
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://normal-website.com" > ]>
```

The URL can use the file:// protocol, and so external entities can be loaded from file. For example:

```xml
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>
```
It's important to note that you could also use `php://`. 

#### php://

##### **What is a Stream Wrapper?**  
A **stream wrapper** in PHP is like a **virtual file system** that lets you read and write data from different sources (files, network, memory, etc.) **using file-like functions** (`fopen()`, `file_get_contents()`, etc.).  

Think of it as a **"translator"** that makes different data sources behave **like files**, even if they aren’t real files.

---

##### **How Stream Wrappers Work**
Normally, when you read a file in PHP:  
```php
$content = file_get_contents("file.txt");
```
PHP knows **`file.txt` is a real file** on disk.  

But **with a stream wrapper**, you can do this:  
```php
$content = file_get_contents("php://input");
```
Even though **there is no actual file called `php://input`**, PHP treats it **like a file** and reads data from the HTTP request body.

---

#### **Types of Stream Wrappers in PHP**
PHP provides different built-in wrappers that work like **fake file paths**:

| Wrapper | What It Does |
|---------|-------------|
| `file://` | Reads/writes actual files on disk. |
| `http://` | Reads remote files from the web. |
| `php://input` | Reads raw POST request data. |
| `php://output` | Captures output before sending it. |
| `php://memory` | Creates a temporary file in RAM. |
| `php://filter` | Applies filters (e.g., base64 encode) to a stream. |

---

#### **Example: Using `php://memory` Instead of a File**
```php
$fp = fopen("php://memory", "w+"); // Opens a temporary memory stream
fwrite($fp, "Hello, World!");      // Writes data to it
rewind($fp);                       // Resets pointer to start
echo fread($fp, 1024);              // Reads data (outputs: Hello, World!)
fclose($fp);                        // Closes the stream
```
- There’s **no actual file on disk**—data is stored in RAM!  
- But **PHP treats it like a file**, so you can use `fopen()`, `fwrite()`, etc.  
