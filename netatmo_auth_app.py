from __future__ import annotations

import json
import os
from dataclasses import asdict
from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from hmac import compare_digest
from secrets import token_hex
from secrets import token_urlsafe
from typing import NamedTuple

import requests
from flask import flash
from flask import Flask
from flask import redirect
from flask import render_template_string
from flask import request
from flask import Response
from flask import session
from flask import url_for


class NetatmoApp(NamedTuple):
    name: str
    redirect_uri: str
    client_id: str
    client_secret: str

    @classmethod
    def from_json(cls, fname: str) -> NetatmoApp:
        try:
            with open(fname) as f:
                if oct(os.stat(fname).st_mode) != '0o100600':
                    print(f'WARNING: {fname!r} has unsafe permissions!')
                return cls(**json.load(f))
        except FileNotFoundError:
            raise SystemExit(
                f'a file called {fname!r} must exist in the current working '
                f'directory: {os.getcwd()}',
            )


@dataclass
class OAuth2Token:
    access_token: str
    refresh_token: str
    expires: int

    @property
    def expired(self) -> bool:
        expires_dt = datetime.fromtimestamp(self.expires, tz=timezone.utc)
        return datetime.now(tz=timezone.utc) > expires_dt

    @classmethod
    def from_file(cls) -> OAuth2Token:
        with open('.netatmo_token') as f:
            return cls(**json.load(f))

    def to_json(self, fname: str) -> None:
        with open(fname, 'w') as f:
            json.dump(asdict(self), f)

        os.chmod(fname, 0o100600)

    def refresh(self) -> None:
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token,
            'client_id': NETATMO_APP.client_id,
            'client_secret': NETATMO_APP.client_secret,
        }
        req = requests.post(
            url='https://api.netatmo.com/oauth2/token',
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'},  # noqa: E501
        )
        req.raise_for_status()
        token_info = req.json()

        self.access_token = token_info['access_token']
        expires = datetime.now(tz=timezone.utc) + \
            timedelta(seconds=token_info['expires_in'])
        self.expires = int(expires.timestamp())
        self.refresh_token = token_info['refresh_token']
        self.to_json('.netatmo_token')


NETATMO_APP = NetatmoApp.from_json('netatmo_app.json')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or token_hex(69)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True


@app.route('/')
def index() -> str:
    token = None
    if os.path.exists('.netatmo_token'):
        token = OAuth2Token.from_file()
    return render_template_string(
        '''\
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Netatmo Auth App</title>
  </head>
  <style>
    body {
      font-family: "Helvetica", "Arial", sans-serif;
    }
    .button {
      background-color: #0d6efd;
      border: none;
      border-radius: 8px;
      color: white;
      padding: 8px;
      font-size: 1rem;
    }
    .button:hover {
      background-color: #205fbd;
    }
    .blurry {
      filter: blur(6px);
      cursor: pointer;
    }
    .flash {
      width: max-content;
      max-width: 85%;
      border: 1px solid #205fbd;
      border-radius: 10px;
      text-align: center;
      padding: 5px;
      padding-left: 20px;
      padding-right: 20px;
      margin: auto;
      margin-top: 1rem;
      margin-bottom: 1rem;
      background-color: #0d6efd44;
    }
    .boxed {
      margin: auto;
      width: max-content;
      max-width: 85%;
      border: 1px solid black;
      border-radius: 10px;
      padding: 6px;
    }
  </style>
  <body>
    <div style="text-align: center">
      <h1>Netatmo Auth App</h1>
      {% with messages = get_flashed_messages() %}
        {% if messages %}
          {% for message in messages %}
            <p class="flash">{{ message }}</p>
          {% endfor %}
        {% endif %}
      {% endwith %}
      {% if token is none %}
        <a href="{{ url_for('oauth_authorize') }}"
          ><button class="button">Login with Netatmo</button></a
        >
      {% else %}
        <div class="boxed">
          <h3 style="margin: 3px">{{ app.name }}</h3>
          <hr />
          <p>
            <b>Access Token:</b>
            <span class="boxed" style="margin-right: 5px; margin-left: 3px">
              <span class="blurry" onclick="show(this);"
                ><code>{{ token.access_token }}</code></span
              >
            </span>
            (click to show)
            <button class="button" onclick="copyToClipboard('{{ token.access_token }}')">
              copy
            </button>
          </p>
          <p>
            <b>Refresh Token</b>:
            <span class="boxed" style="margin-right: 5px; margin-left: 3px">
              <span class="blurry" onclick="show(this);"
                ><code>{{ token.refresh_token }}</code></span
              >
            </span>
            (click to show)
            <button class="button" onclick="copyToClipboard('{{ token.refresh_token }}')">
              copy
            </button>
          </p>
          <b>Expires</b>: <span id="expiry">{{ token.expires }}</span>
          <form method="post" action="/refresh_token">
            <input
              style="margin: 3px"
              class="button"
              type="submit"
              value="Refresh this Token"
            />
          </form>
          <a href="{{ url_for('oauth_logout') }}"
            ><button class="button">Logout</button></a
          >
        </div>
      {% endif %}
      <script>
        function show(element) {
          if (element.classList.contains("blurry")) {
            element.classList.remove("blurry");
          } else {
            element.classList.add("blurry");
          }
        }
        async function copyToClipboard(text) {
          await navigator.clipboard.writeText(text);
        }
      let timestamp_element = document.getElementById("expiry");
      if (timestamp_element != null) {
        const timestamp = parseInt(timestamp_element.innerHTML) * 1000;
        const date = new Date(timestamp);
        timestamp_element.innerHTML = date.toLocaleString()
      }
      </script>
    </div>
  </body>
</html>
''',  # noqa: E501
        token=token,
        app=NETATMO_APP,
    )


@app.route('/login')
def oauth_authorize() -> Response:
    session['state'] = token_urlsafe(69)
    return redirect(
        f'https://api.netatmo.com/oauth2/authorize?'
        f'client_id={NETATMO_APP.client_id}&'
        f'redirect_uri={NETATMO_APP.redirect_uri}&'
        f'scope=read_station&'
        f'state={session["state"]}',
    )


@app.route('/logout')
def oauth_logout() -> Response:
    os.remove('.netatmo_token')
    flash('Successfully Logged Out!')
    return redirect(url_for('index'))


@app.route('/auth-callback')
def oauth_callback() -> str:
    state = request.args['state']
    if 'code' not in request.args:
        flash(f'Did not get Token: {request.args["error"]}')
        return (redirect(url_for('index')))

    code = request.args['code']
    # something went wrong - we do not trust the request (CSRF?)
    if not compare_digest(state, session['state']):
        flash('Comparing the oauth2 state failed, CSRF?')
        return (redirect(url_for('index')))

    data = {
        'grant_type': 'authorization_code',
        'client_id': NETATMO_APP.client_id,
        'client_secret': NETATMO_APP.client_secret,
        'code': code,
        'redirect_uri': NETATMO_APP.redirect_uri,
        'scope': 'read_station',
    }
    req = requests.post(
        url='https://api.netatmo.com/oauth2/token',
        data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'},  # noqa: E501
    )
    if req.status_code != 200:
        flash(
            f'There was an error ({req.status_code}) logging you in: '
            f'{req.json()["error"]}',
        )
        return (redirect(url_for('index')))
    else:
        token_info = req.json()
        expires = datetime.now(tz=timezone.utc) + \
            timedelta(seconds=token_info['expires_in'])
        token = OAuth2Token(
            access_token=token_info['access_token'],
            refresh_token=token_info['refresh_token'],
            expires=int(expires.timestamp()),
        )
        token.to_json('.netatmo_token')
        flash('Created new Token')
        return redirect(url_for('index'))


@app.route('/refresh_token', methods=['POST'])
def refresh_token() -> str:
    token = OAuth2Token.from_file()
    token.refresh()
    flash('Successfully refreshed Token!')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run()
