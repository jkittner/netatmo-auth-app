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
from typing import NamedTuple

import requests
from flask import flash
from flask import Flask
from flask import redirect
from flask import render_template_string
from flask import request
from flask import session
from flask import url_for

app = Flask(__name__)
app.config['SECRET_KEY'] = 'b58573856383a1529896a766cc1f5a658aad1e9244bf3bae0d9460b1698eda5dc5803f36628ebe9651ed'  # noqa: E501


class NetatmoApp(NamedTuple):
    name: str
    redirect_uri: str
    client_id: str
    client_secret: str

    @classmethod
    def from_json(cls, fname: str) -> NetatmoApp:
        with open(fname) as f:
            return cls(**json.load(f))


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
    def from_file(cls, fname: str = '.netatmo_token') -> OAuth2Token:
        with open(fname) as f:
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


NETATMO_APP = NetatmoApp.from_json('app.json')


@app.route('/', methods=['POST', 'GET'])
def index() -> str:
    state = token_hex(69)
    session['state'] = state
    token = None
    if os.path.exists('.netatmo_token'):
        token = OAuth2Token.from_file()

    if request.method == 'POST':
        return redirect(
            f'https://api.netatmo.com/oauth2/authorize?'
            f'client_id={ NETATMO_APP.client_id }&'
            f'redirect_uri={ NETATMO_APP.redirect_uri }&'
            f'scope=read_station&'
            f'state={ state }',
        )
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
    .blurry {
      filter: blur(6px);
      cursor: pointer;
    }
    .flash {
      border: 1px solid black;
      border-radius: 10px;
      text-align: center;
      padding-top: 5px;
      padding-bottom: 5px;
    }
  </style>
  <body>
    <div style="text-align: center">
      {% with messages = get_flashed_messages() %}
        {% if messages %}
          <ul class="flashes">
            {% for message in messages %}
              <p class="flash">{{ message }}</p>
            {% endfor %}
          </ul>
        {% endif %}
      {% endwith %}
      <h1>Authorize App</h1>
      <form method="post" action="" style="margin-bottom: 25px">
        <input type="submit" value="Login to Netatmo" />
      </form>
      {% if token is not none %}
        <li>
          <b>Access Token:</b>
          <span class="blurry" onclick="show(this);">{{ token.access_token }}</span>
          (click to show)
        </li>
        <li>
          <b>Refresh Token</b>:
          <span class="blurry" onclick="show(this);">{{ token.refresh_token }}</span>
          (click to show)
        </li>
        <li><b>Expires</b>: {{ token.expires }}</li>
        <form method="post" action="/refresh_token" style="margin-top: 25px">
          <input
            type="submit"
            value="Refresh this token (expires: {{ token.expires }})"
          />
        </form>
      {% endif %}
      <script>
        function show(element) {
          if (element.classList.contains("blurry")) {
            element.classList.remove("blurry");
          } else {
            element.classList.add("blurry");
          }
        }
      </script>
    </div>
  </body>
</html>
''',  # noqa: E501
        token=token,
    )


@app.route('/oauth_redirect')
def oauth_redirect() -> str:
    state = request.args['state']
    if 'code' not in request.args:
        flash(f'did not get token: {request.args["error"]}')
        return (redirect(url_for('index')))

    code = request.args['code']
    # something went wrong - we do not trust the request (CSRF?)
    if not compare_digest(state, session['state']):
        flash('comparing the state failed')
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
        flash('created new token')
        return redirect(url_for('index'))


@app.route('/refresh_token', methods=['POST'])
def refresh_token() -> str:
    token = OAuth2Token.from_file('.netatmo_token')
    token.refresh()
    flash('successfully refreshed token!', category='success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
