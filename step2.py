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
        
key = '04079698'.encode()
enc = DataEnc(key)
message="rxEaWVdsgHTAya8zx7b6g1sVshb8dWjE1bDmvnzXS9xQXEApeseBoq4zknBKYshdTZ50LjzDIzoIytq0HoCq+xLR4f9G2XjYBhT19ZiWhVL9eObeqhmv9vLckDR6VR8OTLUpYx/KH2p6ITus0hGQUpIgB1HNJkL7/aKNly7guuvyjjcKKgWbuAY7LgAWb5iOJEgSDmImHGqXL17qHyT7/sI54xRAcRM8S+wWPM+b1v242NiG2JdXDIglL/ctkVdhamXVnRJvJM1myIQpmSAQ10V5T0Q3FZIS6opWMIoJBLnoC7lJfSZs3OqYsqn+QueOvZmBKRofS2OVi4OJNVeBzDeYzpTxIBO85xhi/U2jUn5ni7fJPr6VZj+xcfpr2Yxwu+r8PZtVGi33rxBHIGtvrKFf3ofMX5EY+xZWwSFLALTQv62E0FP1ErBQwdZtSwwbLszFP+BeYCtO5LoWBOJvVfyDur7JNGpL8Os0bK+M4Alxst2xNGBvZgl+X/84YCxobXjqJdrYCnTgFNl4vbBvwGcR9cpHgglZetEmq1JXs2VgvDnVhv2cuLdklzFKib7bgfOJ2+lbt23jKZH/5tagyM9uOv/mq4mBz0Vaq4UwVdwqYsgCSXliWu2hErqN3+rKflPJgHKth28/BWH1lK5wO+R0tSTfhnOKSRalMCDFzqOkzL7w2ydUHsYwqVWI+kEF2RQb+wtAaF6DxDo1W15xVRu6EFEy27WE0me9T5bZyF+7/rcBIs6M58X9ESQrwrKUfXIqHNRYpuvpyjvcMYgalDwpfw5Ya3YVWvMr4ar1f3tqJ3dO0vih96Pz079rgT+idSf6PTx4SBOr0STOywBMFCLuLaugfkc/MAOu39IS+OU+uY+gXStfNiqbfe/GQncHfp3AC6y5wk9z3tbPtthbhLt5NKalZA8Sv3BzhYLaBETGrMlkYlqsj4nMgxrkFNhxbWKwrzA51dpgdKHeft6HbUWgNqz3KokqDzMm1RkVpbxlL3kgkX7ptdBGKic8iM8i0JgfL+OHtgfByESOi5qCRwIF+XtxdkzBJ0gtGfliwO+QUHL0lBAbTC72SazlXQu+xtg55DxZUasPblYeZmdFo2qS/mzGpvveP9WByWrSL8Yxy4x13UMK+bmrqYRes3/pBuZLpr0eWv9f7QyayNWHHjfUoAocKjZk8l61U1oMzhYMfuuQDqP5g8kCRSyx0P3Y"
print(enc.des_decrypt(key, message))