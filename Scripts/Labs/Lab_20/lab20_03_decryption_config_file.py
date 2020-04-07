def decrypt_file():
	decrypted_data = ""
	decryption_key = 0x4E

	with open("Scripts/Labs/Lab_20/config.dat", "rb") as encrypted_file:
		encrypted_byte = encrypted_file.read(1)
		while encrypted_byte:
			decrypted_char = int.from_bytes(encrypted_byte, byteorder="big") ^ decryption_key
			if decrypted_char == 0x0:
				decrypted_char = 0x20
			decrypted_data = decrypted_data + chr(decrypted_char)
			encrypted_byte = encrypted_file.read(1)

	return decrypted_data

decrypted_data = decrypt_file()
print("The decrypted config file is: " + decrypted_data)