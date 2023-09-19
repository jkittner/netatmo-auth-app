[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/jkittner/netatmo-auth-app/main.svg)](https://results.pre-commit.ci/latest/github/jkittner/netatmo-auth-app/main)

# netatmo-auth-app

An example oauth2 workflow for using the netatmo API.

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
    - create a file called `netatmo_app.json` with this structure in your current
      working directory
      ```json
      {
        "name": "<name of the app>",
        "redirect_uri": "http://localhost:5000/auth-callback",
        "client_id": "<client_id>",
        "client_secret": "<client_secret>"
      }
      ```
    - set the file permissions to `-rw-------`
      ```bash
      chmod 600 netatmo_app.json
      ```
    - the `redirect_uri` must match your netatmo app's settings
1.  run the app
    - in the terminal run to start the web app:
      ```bash
      netatmo-auth-app
      ```
    - open your browser at http://127.0.0.1:5000
1.  log into your account

    1. click _Login to Netatmo_. You will be redirected to the Netatmo page
    1. Enter your email and password and click _LOG IN_
    1. Click _YES, I ACCEPT_ to allow access to our third-party app
    1. You will be redirected to the local authorization app which now has an access
       token and a refresh token (blurred for your safety). You have to click on the
       blur to remove it and show the token in plain text.
    1. A button shows up, which you can use to refresh the token

1.  a file called `.netatmo_token` is now created in your current working directory,
    which will contain the access token, the refresh token, and the expiry timestamp.
    **Make sure you never check in this file -- add it to your `.gitignore`**

1.  You can use the token in your scripts like this:

```python
from netatmo_auth_app import OAuth2Token

token = OAuth2Token.from_file()
if token.expired:
    token.refresh()
```
