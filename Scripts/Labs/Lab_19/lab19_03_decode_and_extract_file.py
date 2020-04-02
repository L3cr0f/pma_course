MAX_VALUE = 0xFF

def decrypt_file(size, offset):
	decoded_bytes = bytearray()
	key = 0x4A

	with open("Scripts/Labs/Lab_19/Lab19-03.pdf", "rb") as encoded_file:
		encoded_file.seek(offset)
		encoded_byte = int.from_bytes(encoded_file.read(1), byteorder="big")

		while size > 0:
			decoded_byte = (encoded_byte ^ key) & MAX_VALUE
			decoded_bytes.append(decoded_byte)

			key = (key + 1) & MAX_VALUE
			size = size - 1
			encoded_byte = int.from_bytes(encoded_file.read(1), byteorder="big")

	return decoded_bytes

def save_decrypted_file(end_of_name, decoded_bytes):
	decoded_file = open("Scripts/Labs/Lab_19/Lab19-03_stage_" + end_of_name, "wb")
	decoded_file.write(decoded_bytes)


size_1 = 0xA000
offset_1 = 0x106F

decoded_bytes_1 = decrypt_file(size_1, offset_1)
save_decrypted_file("3.exe", decoded_bytes_1)

size_2 = 0x144E
offset_2 = 0xB06F

decoded_bytes_2 = decrypt_file(size_2, offset_2)
save_decrypted_file("4.pdf", decoded_bytes_2)
