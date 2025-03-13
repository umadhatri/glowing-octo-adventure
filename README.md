# Challenges for creation

## 1. Cookie Monster (CSRF with SameSite Bypass)
   **Overview**: A web application has implemented SameSite cookie protections but has configuration flaws that can be bypassed through clever request manipulation.  
   **Difficulty**: Intermediate  
   **Solution**: Exploit cross-site request forgery by leveraging SameSite Lax exceptions through GET requests or by using a subdomain bypass.  
   **Key Concepts**: SameSite cookie attributes, CSRF protections, request method manipulation.

## 2. CORSair (CORS Misconfiguration)
   **Overview**: A secure API implements CORS but has a wildcard subdomain configuration that can be exploited.  
   **Difficulty**: Intermediate  
   **Solution**: Register a malicious subdomain or exploit a reflected XSS on a trusted subdomain to bypass CORS protections.  
   **Key Concepts**: Cross-Origin Resource Sharing, subdomain takeover, origin validation.  

## 3. JWT Cracker (JWT Algorithm Confusion)
   **Overview**: An authentication system using JWTs allows attackers to switch the signing algorithm from RS256 to HS256.  
   **Difficulty**: Intermediate to Advanced  
   **Solution**: Modify the JWT header to change the algorithm and sign the token using the public key as the secret.  
   **Key Concepts**: JWT security, algorithm confusion, cryptographic attacks.

## 4. SQLi Labyrinth (Second-Order SQL Injection)
   **Overview**: Data entered in one part of the application is stored and later used in a SQL query in another part of the application without proper sanitization.  
   **Difficulty**: Advanced  
   **Solution**: Insert malicious SQL in a stored username or profile field that executes when accessed in a different context.  
   **Key Concepts**: Stored/second-order SQL injection, persistent attacks, context switching.  

## 5. Cache Poisoner (Web Cache Poisoning)
   **Overview**: A web application uses caching but doesn't properly validate all inputs that affect the response, allowing attackers to poison the cache.  
   **Difficulty**: Advanced  
   **Solution**: Identify unkeyed inputs (like headers) that affect the response and inject malicious content to be served to other users.  
   **Key Concepts**: Web cache poisoning, unkeyed inputs, mass exploitation.  

## 6. SSRFurf (Server-Side Request Forgery with Internal Service Access)
   **Overview**: A web application allows users to fetch resources from URLs but doesn't properly validate the URLs, allowing access to internal services.  
   **Difficulty**: Intermediate  
   **Solution**: Craft a URL that accesses internal services (like metadata services in cloud environments) to retrieve sensitive information.  
   **Key Concepts**: SSRF, cloud service metadata, internal network access.  

## 7. Deserialized Killer (Insecure Deserialization - PHP)
   **Overview**: A PHP application deserializes user-controlled data without proper validation.  
   **Difficulty**: Advanced  
   **Solution**: Create a malicious serialized object that, when deserialized, triggers method calls leading to code execution.  
   **Key Concepts**: PHP object injection, magic methods, deserialization vulnerabilities.  

## 8. XML Wrecker (XXE Injection with OOB Exfiltration)
   **Overview**: An XML parser that processes user input is vulnerable to XXE, but direct output is not visible.  
   **Difficulty**: Advanced  
   **Solution**: Use out-of-band (OOB) techniques to exfiltrate sensitive data through DNS requests or HTTP callbacks.  
   **Key Concepts**: XXE injection, out-of-band data exfiltration, XML parsers.  

## 9. Regexterminator (ReDoS Attack)
   **Overview**: A web application uses vulnerable regular expressions that can be exploited with carefully crafted inputs.  
   **Difficulty**: Intermediate  
   **Solution**: Create input strings that cause catastrophic backtracking in regex evaluation, causing a denial of service.  
   **Key Concepts**: Regular expression denial of service, algorithmic complexity, input validation.  

## 10. Shell Shocker (Template Injection)
**Overview**: A web application uses a template engine (like Jinja2, Twig, or Handlebars) and allows user input to be incorporated into templates.  
    **Difficulty**: Advanced  
    **Solution**: Inject template syntax to achieve server-side code execution through template evaluation.  
    **Key Concepts**: Server-side template injection, sandboxes, context escaping.
