# Firefox login decryptor

Firefox 75+ password protected login database decryptor.

Implementation based on https://github.com/lclevy/firepwd

## Installation

```
pip install git+https://github.com/siikamiika/firefox-login-decryptor.git
```

## Usage

```python
import getpass
import os
from firefox_login_decryptor import FirefoxLoginDecryptor

profile_dir = os.path.expanduser('~/.mozilla/firefox/asdf.default/')
master_password = getpass.getpass()

decryptor = FirefoxLoginDecryptor(
    profile_dir + 'key4.db',
    profile_dir + 'logins.json',
    master_password
)
for hostname, username, password in decryptor.decrypt():
    print(f'Hostname: {hostname}; Username: {username}; Password: {password}')
```

## Uninstallation

```
pip uninstall firefox-login-decryptor
```
