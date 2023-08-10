[![pre-commit](https://github.com/jkittner/netatmo-auth-app/actions/workflows/pre-commit.yaml/badge.svg)](https://github.com/jkittner/netatmo-auth-app/actions?query=workflow%3Apre-commit)

# netatmo-auth-app

## installation

via ssh

```bash
pip install git+ssh://git@github.com/jkittner/netatmo-auth-app
```

via https

```bash
pip install git+https://github.com/jkittner/netatmo-auth-app
```

## usage

1.  setup your app
    - create a file called `app.json` with this structure in your current working
      directory
      ```json
      {
        "name": "<name of the app>",
        "redirect_uri": "http://localhost:5000/oauth_redirect",
        "client_id": "<client_id>",
        "client_secret": "<client_secret>"
      }
      ```
    - set the file permissions to `-rw-------`
      ```bash
      chmod 600 app.json
      ```
    - the `redirect_uri` must be set in your app's settings and match the one configured
      in this file
1.  run the app
    - in the terminal run to start the web-app:
      ```bash
      netatmo-auth-app
      ```
    - open your browser at http://localhost:5000
1.  log into your account

    1. click _Login to Netatmo_. You will be redirected to the Netatmo page
    1. Enter your email and password and click _LOG IN_
    1. Click _YES, I ACCEPT_ to allow access to our third-party app
    1. You will be redirected to the local authorization app which now has an access
       token and a refresh token (blurred for your safety). You have to click on the
       blur to remove it and show the token in plain text.
    1. A button shows up, which you can use to refresh the token (when it expired or to
       prolong the lifetime)

1.  a file called `.netatmo_token` is now created in your current working directory,
    which will contain the access token, the refresh token, and the expiry timestamp.

1.  You can use the token in your scripts like this:

```python
from netatmo_auth_app import OAuth2Token

token = OAuth2Token.from_file()
if token.expired:
    token.refresh()
```