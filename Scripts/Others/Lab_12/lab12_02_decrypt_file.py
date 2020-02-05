def decrypt_file():
	decrypted_bytes = bytearray()
	key = 0x41

	with open("Scripts/Others/Lab_12/lab12-02_encrypted_payload.ex_", "rb") as encrypted_file:
		encrypted_byte = encrypted_file.read(1)
		while encrypted_byte:
			decrypted_byte = int.from_bytes(encrypted_byte, byteorder="big") ^ key
			decrypted_bytes.append(decrypted_byte)
			encrypted_byte = encrypted_file.read(1)

	return decrypted_bytes

def save_decrypted_file(decrypted_bytes):
	decrypted_file = open("Scripts/Others/Lab_12/lab12-02_decrypted_payload.ex_", "wb")
	decrypted_file.write(decrypted_bytes)

decrypted_bytes = decrypt_file()
save_decrypted_file(decrypted_bytes)