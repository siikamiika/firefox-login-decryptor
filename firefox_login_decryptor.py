"""
Login decryptor class for Firefox 75+ style key4.db + logins.json

Implementation based on https://github.com/lclevy/firepwd
"""

import json
import sqlite3
import base64
import hashlib
import binascii

from pyasn1.codec.der import decoder as asn1der_decoder
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import unpad


class FirefoxLoginDecryptor:

    _CKA_ID = binascii.unhexlify("f8000000000000000000000000000001")

    def __init__(self, key_db_path, logins_json_path, master_password):
        self._key_db_path = key_db_path
        self._logins_json_path = logins_json_path
        self._master_password = master_password

    def decrypt(self):
        key = self._decrypt_key(self._master_password.encode("utf-8"))
        yield from self._decrypt_logins(key)

    def _decrypt_key(self, master_password):
        # firefox 58.0.2 / NSS 3.35 with key4.db in SQLite
        conn = sqlite3.connect(self._key_db_path)
        cur = conn.cursor()
        cur.execute("SELECT item1, item2 FROM metadata WHERE id = 'password'")
        row = cur.fetchone()
        global_salt = row[0]
        item2 = row[1]
        cleartext = self._decrypt_pbe(item2, master_password, global_salt)

        if cleartext == b"password-check\x02\x02":
            cur.execute("SELECT a11, a102 FROM nssPrivate WHERE a11 IS NOT NULL")
            row = cur.fetchone()
            a11 = row[0]  # CKA_VALUE
            a102 = row[1]
            assert a102 == FirefoxLoginDecryptor._CKA_ID
            # decrypt master key
            cleartext = self._decrypt_pbe(a11, master_password, global_salt)
            return cleartext[:24]
        return None

    def _decrypt_logins(self, key):
        with open(self._logins_json_path) as f:
            logins = json.load(f)
        for row in logins["logins"]:
            username = self._decrypt_login_field(row["encryptedUsername"], key)
            password = self._decrypt_login_field(row["encryptedPassword"], key)
            yield row["hostname"], username.decode("utf-8"), password.decode("utf-8")

    def _decrypt_login_field(self, data, key):
        key_id, iv, ciphertext = self._decode_login_field(data)
        assert key_id == FirefoxLoginDecryptor._CKA_ID
        return self._decrypt_des3(key, iv, ciphertext)

    def _decode_login_field(self, data):
        asn1data = asn1der_decoder.decode(base64.b64decode(data))
        key_id = asn1data[0][0].asOctets()
        iv = asn1data[0][1][1].asOctets()
        ciphertext = asn1data[0][2].asOctets()
        return key_id, iv, ciphertext

    def _decrypt_pbe(self, data, master_password, global_salt):
        salt, iteration_count, key_length, iv, ciphertext = self._decode_pbe(data)
        pw = hashlib.sha1(global_salt + master_password).digest()
        key = hashlib.pbkdf2_hmac("sha256", pw, salt, iteration_count, dklen=key_length)
        return self._decrypt_aes(key, iv, ciphertext)

    def _decode_pbe(self, data):
        asn1data = asn1der_decoder.decode(data)
        pbe_algo = str(asn1data[0][0][0])
        # pkcs5 pbes2
        # https://phabricator.services.mozilla.com/rNSSfc636973ad06392d11597620b602779b4af312f6
        assert pbe_algo == "1.2.840.113549.1.5.13"
        assert str(asn1data[0][0][1][0][0]) == "1.2.840.113549.1.5.12"
        assert str(asn1data[0][0][1][0][1][3][0]) == "1.2.840.113549.2.9"
        assert str(asn1data[0][0][1][1][0]) == "2.16.840.1.101.3.4.1.42"
        # https://tools.ietf.org/html/rfc8018#page-23
        salt = asn1data[0][0][1][0][1][0].asOctets()
        iteration_count = int(asn1data[0][0][1][0][1][1])
        key_length = int(asn1data[0][0][1][0][1][2])
        assert key_length == 32
        # https://hg.mozilla.org/projects/nss/rev/fc636973ad06392d11597620b602779b4af312f6#l6.49
        iv = b"\x04\x0e" + asn1data[0][0][1][1][1].asOctets()
        # 04 is OCTETSTRING, 0x0e is length == 14
        ciphertext = asn1data[0][1].asOctets()

        return salt, iteration_count, key_length, iv, ciphertext

    def _decrypt_des3(self, key, iv, ciphertext):
        return unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(ciphertext), 8)

    def _decrypt_aes(self, key, iv, ciphertext):
        return AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
