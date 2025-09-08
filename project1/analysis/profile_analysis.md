# Profile Vulnerabilities
## [CWE-89](https://cwe.mitre.org/data/definitions/89.html): SQL Injection
The profile page is vulnerable to sql injection since the only validation for username and email is that they differ of None. This allows login to be easily bypassed.

Login page simple bypass examples:
Inputting an SQLInjection query as username and making sure it's different of None and doing such for the email field will result in a sucessfull loggin.

Suppose an attacker knows that an account named `user` exists because he saw one of their posts. He can then go to the profile page and input a query as `username` and something as email. This will allow the attacker to impersonate `user`.

### Vulnerability Mitigation
To address this we relied on additional validation functions in the `auth.py` file such as `is_username_valid` and `is_email_valid`. These function detect the presence of any unauthorized character and also enforce username and e-mail requirements.

## [CWE-79](https://cwe.mitre.org/data/definitions/79.html): Cross-site Scripting
The profile page is vulnerable to Cross-site Scripting. An attacker can input an XSS injection when filling the username field. Whenever he viwes a profile the XSS will be run no matter what.

Example:
An attacker validates with the following username: ``totally_innocent<script>alert("hacked")</script>``.
Every time the profile is accessed makes it so it will be infected with this script.

### Vulnerability Mitigation
To address this we relied on additional validation functions in the `auth.py` file such as `is_username_valid`, `is_password_valid` and `is_email_valid`. These function detect the presence of any unauthorized character and also enforce username and e-mail requirements.

## [CWE-23](https://cwe.mitre.org/data/definitions/23.html) Path Traversal
The profile page is vulnerable to path traversal as well, if the attacker alters the url of the profile page, with a certain input he can gain access to other users private profile, with this an attacker can gain personnal information about a user, or in case it's a administrator profile he is presented with some new privileges associated to that roll.

Example:

https://profile/Ligma (attacker can insert all the usernames he knowns to gain access to those same profiles and sensitive information)

Right after the url put '/' followed by someone else's username, this will cause the directory to change and reach that same private profile, as shown above, if the hacker gets his hands on a users username.
With this CWE the attacker could modify or read files, change directories, overwrite and delete critical files or data, etc.

### Vulnerability Mitigation
To address this we do not pass the username in the directory of the html page's url, this way the attacker can not get access to other users profiles, using path traversal, this is complemented by the 'is_username_valid' to verify the authenticity of the login.

## [CWE-306](https://cwe.mitre.org/data/definitions/306.html) Missing Authentication for Critical Function
The profile page is also vulnerable to users that aren't logged in, which means that there is no authentication and the user can still access the profile page. With this the attacker can gain access to very restrict data of users such as email, username and comments as well as more privileges when this vulnerability is implemented to an administrator. This can have a large impact if it's for example a bank app where the users profile contains data such as balance, last moves made in the account and much more data.

### Vulnerability Mitigation
To address this vulnerability we relied on additional validation functions in the auth.py file such as get_logged_in_user and get_logged_in_admin. These functions verify the authenticity of the login while also checking if the person logged on is a user or an admin.
With this 2 lines of code are used exactly to achieve that purpose:

if auth.get_logged_in_user(session) is None:

return redirect(url_for("main_page"))

if auth.get_logged_in_admin(session) is None:

return redirect(url_for("main_page"))


# Acknoledgements
  - https://cwe.mitre.org/data/definitions/89.html
  - https://cwe.mitre.org/data/definitions/23.html
  - https://cwe.mitre.org/data/definitions/306.html
  - https://cwe.mitre.org/data/definitions/79.html
  - https://cwe.mitre.org
  - https://jinja.palletsprojects.com/en/3.0.x/
  - https://flask.palletsprojects.com/en/2.0.x/
  - https://docs.python.org/3/library/sqlite3.html
  - https://getbootstrap.com/docs/5.1
  - https://wiki.owasp.org/index.php/Path_Traversal
  - https://wiki.owasp.org/index.php/Main_Page
  - https://wiki.owasp.org/index.php/Cross-site_Scripting_(XSS)
  - https://wiki.owasp.org/index.php/No_authentication_for_critical_function
  - https://wiki.owasp.org/index.php/PL/SQL:SQL_Injection
