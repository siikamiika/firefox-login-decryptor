from setuptools import setup

setup(
    name='firefox_login_decryptor',
    version='0.0.1',
    url='https://github.com/siikamiika/firefox-login-decryptor.git',
    author='siikamiika',
    description='Firefox 75+ password protected login database decryptor',
    packages=['firefox_login_decryptor'],
    package_dir={'firefox_login_decryptor': 'src'},
    install_requires=['pycryptodome', 'pyasn1'],
)
