# [Portswigger](#portswigger)
  - [SQL Injection](#sql-injection)
  - [Cross-site Scripting](#cross-site-scripting)
  - [Cross-site request forgery](#csrf)
  - [Clickjacking](#clickjacking)
  - [DOM based vulnerabilities](#dom-based-vulnerabilities)
  - [Cross-origin resource sharing](#CORS)
  - [XML external entity (XXE) injection](#xxe-injection)
  - [Server-side request forgery](#ssrf)
  - [HTTP request smuggling](#HTTP-request-smuggling)
  - [OS command injection](#OS-command-injection)
  - [Server-side template injection](#Server-side-template-injection)
  - [Directory traversal](#directory-traversal)
  - [Access control vulnerabilities](#Access-control-vulnerabilities)
  - [Authentication](#authentication)
  - [Websockets](#websockets)
  - [Web cache poisoning](#Web-cache-poisoningn)
  - [Insecure deserialization](#Insecure-deserialization)
  - [Information disclosure](#Information-disclosure)
  - [Business logic vulnerabilities](#Business-logic-vulnerabilities)
  - [HTTP Host header attacks](#HTTP-Host-header-attacks)
  - [OAuth authentication](#OAuth-authentication)

## OWASP

### SQL Injection

### Cross Site Scripting

### CSRF

### Clickjacking

### DOM based vulnerabilities

### CORS

### XXE Injection

### SSRF

### HTTP request smuggling

### OS command injection

### Server-side template injection

### Directory traversal

### Access control vulnerabilities

### Authentication

### WebSockets

### Web cache poisoning

### Insecure deserialization

### Information disclosure

#### About Information Disclosure =>

* also known as information leakage, a website unintentionally reveals sensitive information to its users
* Information Like  => Data about other Users , such as Username or financial information
* Information Like=>Sensitive commercial or business data
* Information Like => Technical details about the website ad its infrastructure
* Can lead to other vulnerabilities

#### Examples ==> 

* Revealing the names of hidden directories, their structure, and their contents via a robots.txt file or directory listing
* Providing access to source code files via temporary backups
* Explicitly mentioning database table or column names in error messages
* Unnecessarily exposing highly sensitive information, such as credit card details
* Hard-coding API keys, IP addresses, database credentials, and so on in the source code
* Hinting at the existence or absence of resources, usernames, and so on via subtle differences in application behavior

#### Developer make mistake like =>

* Fail to remove internal content from public
* Insecure configuration use by default
* Make flawed design and behvior of application


NOTE : Our main focus on the IMPACT & Exploitability of the leaked information


#### Testing for Information Disclosure =>

```Sensitive data can be leaked in all kinds of places, so it is important not to miss anything that could be useful later. ```


#### 1. Fuzzing  & Burp Scanner  & Burp's Engagement Tool =>

* If got Interesting Parameter -> Try to submit Unexpected data types there and FUZZ that parameter with lots of Payloads -> And then Observer behavior of Target i.e. Unusual Response
* One error can be useful for another thing, so keep an eye on this
* Tool use -> Burp  Intruder
* Check carefully -> HTTP status codes, response times, lengths, and so on.
* Use grep matching rules to quickly identify occurrences of keywords, such as error, invalid, SELECT, SQL, and so on.
* Apply grep extraction rules to extract and compare the content of interesting items within responses.
* Useful Extension -> Logger++
* Burp Scanner -> will alert you if it finds sensitive information such as private keys, email addresses, and credit card numbers in a response
* also identify any backup files, directory listings, and so on
* can access the engagement tools from the context menu - just right-click on any HTTP message, Burp Proxy entry, or item in the site map and go to "Engagement tools".
* Important Burp Tool -> Search, Find Comments, Discover Contents


#### 2.  Engineering informative responses =>

* Verbose error messages can sometimes disclose interesting information while you go about your normal testing workflow
*  submitting an invalid parameter value might lead to a stack trace or debug response that contains interesting details. 
*  We can sometimes cause error messages to disclose the value of our desired data in the response.


#### Common Sources of Information Disclosure =>

* Files for Web Crawlers -> robots.txt , sitemap.xml

*  Directory Listings i.e leaking the existance and location of sensitive resource to public

*  Developer Comments -> developer often forget to remove sensitive comments from html page or even in JS

*  Verbose Error Messages ->
	* most common causes of information disclosure 
	* pay attention to all error messages while auditing or testing target 
	* It might expose : name a template engine, database type, or server that the website is using, along with its version number etc 
	* Check for source code
	* Useful for -> SQLi, Username Enumeration etc


* Debugging data -> 
	* During Devleopment phase Developer debug data to check for error message and logs (which contain large amounts of information about application's behavior)
	* Good in during Development phase But not good if Devleoper expose this things to public Accidently or forgot to remove this information while making target live from development phase
	* Valuable Information from Debugging Data include ->
		* Values for key session variables that can be manipulated via user input
		* Hostnames and credentials for back-end components
		* File and directory names on the server
		* Keys used to encrypt data transmitted via the client
	* Debugging information may sometimes be logged in a separate file.
	* Goal of an attacker is to obtain this file


*  User account pages ->
	* User's Profile page or "My Account" page usually contain -> sensitive Information -> like email address, phone number, API key and so on
	* **Business Logic Flaws**  vulnerability on such Application's Functions can lead to Information Leakage and hence can be use for Account Takeover
	* By **Business Logic Flaws** Attacker can view other user's data
	* So, keep an eye on such Functionalities , like -> GET /user/personal-info?user=carlos


* Source code disclosure via backup files ->
	* Source code contains often Sensitive data
	* Example -> API keys and credentials for accessing back-end components.
	* Sometime, we can see a backup file present on web server
	* To get this just try this -> filename.php to -> filename.php~ [ that is use tilde ~]
	* Also to try -> .bak extra


* Information disclosure due to insecure configuration ->
	* Websites are sometimes vulnerable as a result of improper configuration
	* commonly due to the widespread use of third-party technologies, whose vast array of configuration options are not necessarily well-understood by those implementing them. 
	* Also, developers might forget to disable various debugging options in the production environment
	* Example ->  
		* HTTP TRACE method is designed for diagnostic purposes.
		* If enable. the web server will respond to requests that use the TRACE method by echoing in the response the exact request that was received. 
		* This behavior leads to information disclosure, such as the name of internal authentication headers that may be appended to requests by reverse proxies.


* Version control history ->
	* Check for .git directory
	* Try various ways to get or enumerate on .git directory for juicy information
	* Check website's version control history of .git
	* This may include logs containing committed changes and other interesting information.


============================================================================

#### Lab Solution =>

#### 1. Unprotected admin functionality with unpredictable URL =>

* Check target page , source page, and check JS, it disclose the URL of admin panel => /admin-u4shhr
* Just go to that admin panel and do what ever we want


#### 2.   Information disclosure in error messages =>

* Here just normal browse target and check parameters what given to users
* When testing for parameters just give unwanted things to that parameter like -> id=2" or id=unwanted-things and this will expose version of server use on page as Error


#### 3. Information disclosure on debug page =>

* Just check view source and there check for comments for debug purpose or even ctrl+f for either comments or debug -> like -> ```<!--  or "debug"```
* got -> ```<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->```


#### 4.  User ID controlled by request parameter with data leakage in redirect =>

* Here just need to change id of user on GET Parameter of "My Account" page and if misconfigure then we can access other user data 
* Here the target redirect when trying to view other user by changing user to victim name
* But still the sensitive data can be accessible on the body of a web page


#### 5. Arbitrary object injection in PHP =>

* This lab use -> serialization-based session mechanism
* From view-source -> check comment -> got -> /libs/CustomTemplate.php
* just change this file to -> /libs/CustomTemplate.php~
* We can see php source code, now just analyze it and do further attack accordingly
* PHP Code using -> CustomTemplate class and contains the **__destruct() magic method**
* This will invoke the unlink() method on the lock_file_path attribute, which will delete the file on this path
* Use Burp Decoder and use correct Syntax for Serialized PHP Data to create a CustomTemplate object with the lock_file_path attribute set to /home/carlos/morale.txt.
* O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
* Base64 and URL-encode this object and save it to your clipboard
* Send a request containing the session cookie to Burp Repeater.
* In Burp Repeater, replace the session cookie with the modified one in your clipboard.
* Send the request. **The __destruct() magic method is automatically invoked and will delete Carlos's file.**


Myself Note: though i solved this above lab but i still not understand this Seriliazed based injection


#### 6. Source code disclosure via backup files =>

* From robots.txt -> got /backup dir
* Got from that dir -> /backup/ProductTemplate.java.bak
* This contain source code of java file and there we can see DB Password 


#### 7.  Authentication bypass via information disclosure =>

* Go to /admin directory -> available to user only
* So, change the GET Header to TRACE header to /admin page
* In Response -> X-Custom-IP-Authorization header came -> Contain our IP Address -> which is used to determine whether or not the request came from the localhost IP address.
* From Burp -> Proxy --> Match and Replace -> Click "Add"  -> Leave the match condition blank -> in Replace Field  enter : X-Custom-IP-Authorization: 127.0.0.1
* Burp Proxy will now add this header to every request we send.
* Now, we can go to home page, and we can see admin panel accessable and do whatever we want


#### 8. Information disclosure in version control history =>

* Just try to enter .git on the browser of target
* We can download this repo and check for juicy information there
* There is a commit -> Remove admin password from config
* Use diff command  for the changed admin.conf file
* We can see admin password with an environment variable ADMIN_PASSWORD instead
* Use that password as administrator and do whatever we want


==========================================================================

#### Summary =>

* Just focus on everything the target can disclose about sensitive information from various ways like ->
* forced browsing, 
* verbose error message, 
* debug enable, 
* directory showing, 
* comment useful on source view, 
* backup file, 
* ~ [tilde] ,
*  try to input unusual data and even try every character which can be response from target as useful for attackers
*  .git directory
*  Other HTTP Header Method -> TRACE

### Business logic vulnerabilities

### HTTP Host header attacks

### OAuth authentication
