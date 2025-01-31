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
