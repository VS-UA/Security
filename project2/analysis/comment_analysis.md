# SQL Injection and XSS

There is no verification of the text input on the comment page, therefore it is easy to make SQL injection and XSS just by creating a comment.

## XSS Mitigation

In order to mitigate XSS, [bleach](https://github.com/mozilla/bleach) was used. It is an allow list based filter made to sanitize HTML text input.

With an allow list based filter, only certain tags and atributes don't get pre processed. 
This allows for some limited markup syntax.
For instance, a user can type `<em>My italic comment<em>` and the comment will be in italic.

### Other aproaches 

Another usefull tool (although incomplete) is to encode data before incorporating into an HTML element. 
This means replacing XML significant characters for their HTML codes, for instance `&` would be replaced by `&amp;`.

Like this encoder, many others exist (see [this article](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)), however, since the library we used already contains these none were manually implemented.

## Example XSS attacks

In the insecure version basic stored XSS is very easy to do.
Going to the comments page and commenting `<script>alert("I got your credit card!")</script>` will create an empty comment that will execute this javascript code in every page access made by every user.

In the secure version, bleach processes this input in a way that the comment is displayed as "\<script\>alert("I got your credit card!")\</script\>", so, no code is executed.

## SQL Injection mitigation

In order to prevent SQL injection, we used prepared statements with parametrised queries from sqlite. With this, sqlite's driver takes the text to be inserted in the query and treats it to be interpreted as the correct data type.

For instance, if someone adds a comment with `SELECT password FROM usr; -- //` (it wouldn't show all passwords, but it's short and descriptive enought to demonstrate the idea), sqlite3 would escape it in a way that would create a comment with the text "SELECT password FROM usr; -- //", as the app's behaviour should be.

There are, however, more options to deal with this.

### Other aproaches

There are third party tools (some listed [here](https://www.esecurityplanet.com/threats/how-to-prevent-sql-injection-attacks/)) that do allow list input validation. 
However, they are not perfect, and since a sanitization tool is already used to [protect against XSS](#xss-mitigation) none of these tools were used.

SQLite also allows the use of stored procedures, which store the queries in the database itself and get the data through variable binding.
Since this does almost the same as parametrised queries we opted not to use this. Also even OWASP recognises it is not needed to combine both.

## SQL Injection example attacks

In the insecure app, a user can comment any typical SQL injection query and it will be processed as such.

For instance, if a user comments `' || (SELECT GROUP_CONCAT(password_hash || " , " || username || "<br>") FROM usr)); -- //` the comment will be a list of password hashes followed by the username they belong to.

On the secure version, however, the comment will have this exact query's text, not the passwords and usernames.

# Acknowledgements

- https://bleach.readthedocs.io/en/latest/
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- https://www.esecurityplanet.com/threats/how-to-prevent-sql-injection-attacks/
