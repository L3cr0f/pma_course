from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii

decryption_key = b'ijklmnopqrstuvwx'
encrypted_data = binascii.unhexlify('37f31f045120e0b586acb60f652089924faf98a4c87698a64dd5518fa5cb51c5cf86110dc535385c9cc5ab6678401ddf4a53f0110f576d4fb7c9c8bf29792fc1ec60b223007b28fa4dc17b8193bbca9ebb27dd47b6be0b0f661095179ed7c48dee11099920493bdfdebe6eef6a12dbbda676b02213eea9382d2f560678cb2f91af64afa6d143f1f547f6c2c86f004939')

cipher = AES.new(decryption_key, AES.MODE_CBC)
decrypted_string = cipher.decrypt(pad(encrypted_data, 16))

print("The decrypted string is: " + decrypted_string)