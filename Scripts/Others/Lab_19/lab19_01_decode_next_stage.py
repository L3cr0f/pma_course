MAX_VALUE = 0xFF

def decrypt_file():
	decoded_bytes = bytearray()
	key = 0x41
	counter = 0x18D

	with open("Scripts/Others/Lab_19/lab19-01.bin", "rb") as encoded_file:
		encoded_file.seek(0x224)
		encoded_byte = encoded_file.read(1)

		while counter > 0:
			value_1 = (((int.from_bytes(encoded_byte, byteorder="big") - key) & MAX_VALUE) << 4) & MAX_VALUE
			encoded_byte = encoded_file.read(1)

			value_2 = (int.from_bytes(encoded_byte, byteorder="big") - key) & MAX_VALUE
			decoded_byte = (value_2 + value_1) & MAX_VALUE
			decoded_bytes.append(decoded_byte)

			counter = counter - 1
			encoded_byte = encoded_file.read(1)

	return decoded_bytes

def save_decrypted_file(decoded_bytes):
	decoded_file = open("Scripts/Others/Lab_19/lab19-01_stage_2.bin", "wb")
	decoded_file.write(decoded_bytes)

decoded_bytes = decrypt_file()
save_decrypted_file(decoded_bytes)