# Login/Register vulnerabilities

## [CWE-89](https://cwe.mitre.org/data/definitions/89.html): SQL Injection
Both the login and register pages are vulnerable to sql injection since neither of them do any input validation other than checking if the data (username, email, passsword) is not empty. This allows login to be easily bypassed.

Login page simple bypass examples:
Inputting `' OR 1 --//` as username and anything as a password will result in a sucessfull loggin.

Suppose an attacker knows that an account named `user` exists because he saw one of their posts. He can then go to the login page and input `test' -- //` as `username` and anything as password. This will allow the attacker to impersonate `user` and create posts and replies as him.

### Vulnerability Mitigation
To address this we relied on additional validation functions in the `auth.py` file such as `is_username_valid`, `is_password_valid` and `is_email_valid`. These function detect the presence of any unauthorized character and also enforce username, password and e-mail requirements.

## [CWE-79](https://cwe.mitre.org/data/definitions/79.html): Cross-site Scripting
The register page is not only vulnerable to sql injection but also to XSS. An attacker can create an account and inject XSS into his username. Whenever he creates a post/reply the XSS will be run no matter what the text of the comment/reply is making it harder to detect.

Example:
An attacker creates an account with the following username: ``totally_innocent<script>alert("hacked")</script>``.
Every post/reply he makes will be infected with this script.

### Vulnerability Mitigation
To address this we relied on additional validation functions in the `auth.py` file such as `is_username_valid`, `is_password_valid` and `is_email_valid`. These function detect the presence of any unauthorized character and also enforce username, password and e-mail requirements.

## Password Related Vulnerabilities

## [CWE-328](https://cwe.mitre.org/data/definitions/328.html): Use of Weak Hash
Suppose an attacker abuses SQL Injection in the main page. This attacker creates a post with the following content ``Haha, i dumped all your passwords!!!<br>' || (SELECT GROUP_CONCAT(password_hash || " , " || username || "<br>") FROM usr)); -- //`` 
This will dump all passwords hashes in a reasonably readable format. 
The attacker and everyone who sees the post can now see all password hashes. Someone naive might think this is not really a big problem, after all, these are non reversable hash functions. They would be right about the last part but this is not ok, it's a really big problem because the hash function used here is SHA-1, a vulnerable hashing function. SHA-1 is vulnerable to collision attacks.

### Vulnerability Mitigation
To mitigate this we use bcrypt. bcrypt is made to be "slow" and hard to parallelize. bcrypt allows the developer to adjust the computational effort as required. The point is to make brute-force attacks harder and allow the hashing difficulty to scale as processing power increases.

## [CWE-759](https://cwe.mitre.org/data/definitions/759.html): Use of a One-Way Hash without a Salt
Suppose an attacker has dumped all password hashes with methods explained before. Such an attack could have been mitigated by the use of salted passwords. This consists of generating a unique random sequence of characters during account creation to add to the password before hashing (salt is also stored in the database with the password hash). The intention here is to make lookup-table and rainbow-table attacks more difficult. Using salted passwords is not an effective defense against dictionary and brute force attacks since the salt is known.

To demonstrate how salts increase password cracking efforts let's take the following password (`Peanutbutterjellytime1`) and its SHA-1 hash (`2277296f6ff1026bc50afb680bf210e8c6742997`). This password has significant length but it's made of mostly dictionary words and one common number. Using something easily available online like [CrackStations's Free Password Hash Cracker](https://crackstation.net/) we can figure out the original password with minimal effort.
Now suppose we add the following salt (`[nJ5)E2v=Ut^V8Ue`) to the password before hashing. The password hash is now (`0056a80f527dca2c4268f4dd4049402b2e466a5f`). When we input this hash in [Crackstation](https://crackstation.net/) we can see it found no results.

### Vulnerability Mitigation
To mitigate this we, as mentioned before, use bcrypt. bcrypt automaticaly generates a unique salt for each password.

## [CWE-521](https://cwe.mitre.org/data/definitions/521.html): Weak Password Requirements
Suppose an attacker has dumped all password hashes with methods explained before. Weak passwords will be very easy to brute-force even if the passwords are salted because they are either too small or contain dictionary words.

Suppose `user` has a weak password and an attacker obtains his passwords's SHA-1 hash (`7110eda4d09e062aa5e4a390b0a572ac0d2c0220`).
An attacker could simply take this hash and use available online dictionaries like [CrackStations's Free Password Hash Cracker](https://crackstation.net/) to figure out that the password is `1234`.

### Vulnerability Mitigation
To mitigate this we enforce stricter password requirements. A password must have 12 or more characters and be composed of at least one number, one a-z character and one A-Z character.


## Cookie Related Vulnerabilities

## [CWE-565](https://cwe.mitre.org/data/definitions/565.html): Reliance on Cookies without Validation and Integrity Checking
Cookies are used to verify if a user is logged in. They, like the username in the login forms, are not validated and simply trusted.
An attacker can simply modify his cookies to inject sql.

Suppose an attacker knows that an account named `user` exists because he saw one of their posts.
He then creates 2 cookies in his browser, one named `username` with value ``user' -- //`` and another named `password` with any value. This will allow the attacker to impersonate `user` and create posts and replies as him.

### Vulnerability Mitigation
To mitigate this we use flask sessions which are encrypted with a key only the server knows. This makes it extremely hard for an attacker to modify the cookies wihout knowing the key.
The data retrieved from flask sessions is also validated by ``get_logged_in_user`` and ``has_session_expired`` in ``auth.py`` before being used in any kind of operation.

## [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html): Sensitive Cookie Without 'HttpOnly' Flag
When a user sucessfully logs in we set 2 cookies containing the username and password hash without the 'HttpOnly' flag set. This means an attacker could abuse XSS in a post/reply to extract our cookies and do whatever he wants with them.

For example an attacker could abuse XSS and create a post with the following content:
```html
<script>
function sendData( data ) {
  const XHR = new XMLHttpRequest(),
        FD  = new FormData();
  for( name in data ) {
    FD.append( name, data[ name ] );
  }
  XHR.open( "POST", "comment" );
  XHR.send( FD );
} sendData( {text:document.cookie} )
</script>
```
Every time a logged in user loads this page, they will be creating a new post with all of their cookies for everyone to see.

### Vulnerability Mitigation
To mitigate this we use flask sessions which internally also use cookies. We can enable the 'HttpOnly' flag in flask sessionsby setting ``SESSION_COOKIE_HTTPONLY=True`` in flask configuration. This means even if an attacker could abuse XSS in our website he would not be able to access our authentication related cookies.

# Acknoledgements
- https://cwe.mitre.org
- https://jinja.palletsprojects.com/en/3.0.x/
- https://flask.palletsprojects.com/en/2.0.x/
- https://emailregex.com/
- https://getbootstrap.com/docs/5.1
- https://getbootstrap.com/docs/5.1/examples/footers/#
- https://stackoverflow.com/a/20352949
- https://getbootstrap.com/docs/3.4/examples/sticky-footer-navbar/#
- https://developer.mozilla.org/en-US/docs/Learn/Forms/Sending_forms_through_JavaScript
- https://crackstation.net/
- https://pypi.org/project/bcrypt/
- https://docs.python.org/3/library/sqlite3.html
