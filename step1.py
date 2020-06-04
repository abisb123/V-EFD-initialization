import Padding
from Crypto.Cipher import DES
import json
import base64
import hashlib


class DataEnc:

    def __init__(self, key):
        self.cipher = DES.new(key, DES.MODE_ECB)
        self.hash = hashlib.md5()

    @staticmethod
    def pad(data):
        return Padding.appendNullPadding(data, 8).encode()

    def content_sign(self, data):
        self.hash.update(data)
        b_64 = base64.b64encode(self.hash.digest())
        return b_64.decode()

    def des_encrypt_64encode(self, data):
        data_encrypt = self.cipher.encrypt(data)
        return base64.b64encode(data_encrypt)

    @staticmethod
    def des_decrypt(d_key, message):
        cipher = DES.new(d_key, DES.MODE_ECB)
        message = base64.b64decode(message)
        data_decrypt = cipher.decrypt(message) # returns decrypted byte strings
        data_decrypt_rm_pad = Padding.removeNullPadding(data_decrypt.decode(), 8) # removes padding from byte string
        return data_decrypt_rm_pad.encode()
    def encrypted_content(self, data):
        data = str(json.loads(data))
        data = self.pad(data)  # add padding
        data = self.des_encrypt_64encode(data)  # DES encrypt data
        return data.decode()  # convert from bytes to string

bus_data = '{"license": "520404079698", "sn": "LAMASAT INTERNATIONAL LTD", "sw_version": "1.2", "model": "IP-100", ' \
'"manufacture": "Inspur", "imei": "100159197500000", "os": "linux2.6.36", "hw_sn": ""} '
key = '04079698'.encode()
enc = DataEnc(key)

encrypted_business_data = enc.encrypted_content(bus_data)
sign = enc.content_sign(encrypted_business_data.encode())

print("Content value =", encrypted_business_data)
print("Sign value =",sign)
