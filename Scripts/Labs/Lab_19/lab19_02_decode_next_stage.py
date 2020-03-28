MAX_VALUE = 0xFF

def decrypt_file():
	decoded_bytes = bytearray()
	key = 0xE7
	counter = 0x18F

	with open("Scripts/Labs/Lab_19/lab19-02.bin", "rb") as encoded_file:
		encoded_file.seek(0x18)
		encoded_byte = int.from_bytes(encoded_file.read(1), byteorder="big")

		while counter > 0:
			decoded_byte = (encoded_byte ^ key) & MAX_VALUE
			decoded_bytes.append(decoded_byte)

			counter = counter - 1
			encoded_byte = int.from_bytes(encoded_file.read(1), byteorder="big")

	return decoded_bytes

def save_decrypted_file(decoded_bytes):
	decoded_file = open("Scripts/Labs/Lab_19/lab19-02_stage_2.bin", "wb")
	decoded_file.write(decoded_bytes)

decoded_bytes = decrypt_file()
save_decrypted_file(decoded_bytes)