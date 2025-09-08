# Path Traversal and Missing Authentication for Critical Function

The fact that the link to this page is not on the nav bar or anywhere else on the site does not make it secure. Attackers can use dictionary or bruteforce attacks to guess common page names (like `admin`) and get access to hidden locations. It is mandatory to require authentication to acess this link.

The explaination of the login functions is already detailed in the analysis of the login and register pages.

This page is not very feature complete, however, it shows how an administrator-only page needs to be secured even if there is no specific link to it.

## Example attacks

Any logged in user can acess the admin page, not only the admins as it should be. 
To acess it, simply append `/admin` to the home page's URL.
A non logged in attacker will be redirected to the main page, however, a logged in user will be granted full access.

However, a non authenticated user can still do damage. If an attacker knows the form structure (or guesses it by trial and error) they can send the POST request anyways.
On linux, using curl, an atacker can run `curl -X POST -F 'opt=adm' -F 'user=<username>' <link to admin page>` to set `<username>` as admin. Swapping `opt=adm` for `opt=del` would delete the user.

On the secure version this no longer happens. If the user is not an administrator they will be redirected to the main page.

## Mitigation

In order to mitigate this vulnerability, the admin page (both `POST` and `GET` method handlers) should be checking for authentication. 
This way, no unpriviledged user can access the page or use it's methods.
