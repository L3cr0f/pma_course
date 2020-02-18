import os
import sys

MAX_VALUE = 0xFFFFFFFF
MAX_BYTE_VALUE = 0xFF
INT_BITS = 32

# Left rotate of bits
def rotl(num, bits):
	return ((num << bits)|(num >> (INT_BITS - bits))) & MAX_VALUE

# Saves the decrypted file
def save_decrypted_file(file, decrypted_bytes):
	decrypted_file = open(file + "_decrypted.bmp", "wb")
	decrypted_file.write(decrypted_bytes)

# Creates an array of 17 elements, 68 bytes in total
def initialize_key():
	return [0] * 17

# Creates the first auxiliary array, it is used to create the second part of the key
def setup_first_auxiliar_array(key):
	first_auxiliar_array = []

	# We fill the indexes 8 to 15 (included) of the array, which corresponds with bytes 32 to 63, with the values of the key
	for counter in range(8, 16):
		first_auxiliar_array.append(key[counter])

	return first_auxiliar_array

# Gets the value of every element of the second auxiliary array
def get_value_of_second_auxiliar_array(key_value):

	num_1 = key_value & 0xFFFF
	num_2 = key_value >> 0x10
	num_3 = (num_1 * num_1) & MAX_VALUE
	num_4 = num_3 >> 0x11
	num_5 = (num_1 * num_2) & MAX_VALUE
	num_6 = (num_4 + num_5) & MAX_VALUE
	num_7 = num_6 >> 0xF
	num_8 = (num_2 * num_2) & MAX_VALUE
	num_9 = (num_7 + num_8) & MAX_VALUE
	num_10 = (key_value * key_value) & MAX_VALUE

	value = num_9 ^ num_10

	return value

# Creates the second auxiliary array, it is used to create the first part of the key
def setup_second_auxiliar_array(key):
	second_auxiliar_array = []

	# We fill the indexes 0 to 7 (included) of the array, which corresponds with bytes 0 to 31, with the values of the key
	for counter in range(8):
		argument = (key[counter] + key[counter + 8]) & MAX_VALUE
		value = get_value_of_second_auxiliar_array(argument)
		second_auxiliar_array.append(value)

	return second_auxiliar_array

# Gets the first part of the key, it is used as initialization of the first part of the key
def get_second_part_of_key(key, first_auxiliar_array):
	num_1 = key[16]

	for i in range(8, 16):
		num_2 = key[i]
		if i % 3 == 2:
			value = (num_2 + num_1 + 0x4D34D35D) & MAX_VALUE
		elif i % 3 == 0:
			value = (num_2 + num_1 - 0x2CB2CB2D) & MAX_VALUE
		elif i % 3 == 1:
			value = (num_2 + num_1 + 0x34D34D34) & MAX_VALUE

		key [i] = value

		if first_auxiliar_array[i - 8] < value:
			num_1 = 0
		else:
			num_1 = 1
	
	key[16] = num_1 & MAX_VALUE

	return key

# Gets the first part of the key, this is what is going to be used for the encryption process
def get_first_part_of_key(key, second_auxiliar_array):

	num_1 = rotl(second_auxiliar_array[7], 0x10)
	num_2 = (second_auxiliar_array[0] + num_1) & MAX_VALUE
	num_3 = rotl(second_auxiliar_array[6], 0x10)
	key[0] = (num_2 + num_3) & MAX_VALUE

	num_1 = rotl(second_auxiliar_array[0], 0x8)
	num_2 = (second_auxiliar_array[1] + num_1) & MAX_VALUE
	key[1] = (second_auxiliar_array[7] + num_2) & MAX_VALUE
	
	num_1 = rotl(second_auxiliar_array[1], 0x10)
	num_2 = (second_auxiliar_array[2] + num_1) & MAX_VALUE
	num_3 = rotl(second_auxiliar_array[0], 0x10)
	key[2] = (num_2 + num_3) & MAX_VALUE

	num_1 = rotl(second_auxiliar_array[2], 0x8)
	num_2 = (second_auxiliar_array[3] + num_1) & MAX_VALUE
	key[3] = (second_auxiliar_array[1] + num_2) & MAX_VALUE

	num_1 = rotl(second_auxiliar_array[3], 0x10)
	num_2 = (second_auxiliar_array[4] + num_1) & MAX_VALUE
	num_3 = rotl(second_auxiliar_array[2], 0x10)
	key[4] = (num_2 + num_3) & MAX_VALUE

	num_1 = rotl(second_auxiliar_array[4], 0x8)
	num_2 = (second_auxiliar_array[5] + num_1) & MAX_VALUE
	key[5] = (second_auxiliar_array[3] + num_2) & MAX_VALUE

	num_1 = rotl(second_auxiliar_array[5], 0x10)
	num_2 = (second_auxiliar_array[6] + num_1) & MAX_VALUE
	num_3 = rotl(second_auxiliar_array[4], 0x10)
	key[6] = (num_2 + num_3) & MAX_VALUE

	num_1 = rotl(second_auxiliar_array[6], 0x8)
	num_2 = (second_auxiliar_array[7] + num_1) & MAX_VALUE
	key[7] = (second_auxiliar_array[5] + num_2) & MAX_VALUE

	return key

# Gets the key of every iteration
def get_key(key):
	first_auxiliar_array = setup_first_auxiliar_array(key)
	key = get_second_part_of_key(key, first_auxiliar_array)
	second_auxiliar_array = setup_second_auxiliar_array(key)
	key = get_first_part_of_key(key, second_auxiliar_array)

	return key

# Decrypts the file
def decrypt_file(file):
	decrypted_bytes = bytearray()

	key = initialize_key()

	with open(file, "rb") as encrypted_file:
		encrypted_bytes = encrypted_file.read(0x10)
		while encrypted_bytes:
			key = get_key(key)

			# Decryption of the first chunk of 4 bytes (LITTLE ENDIAN)
			encrypted_bytes_0 = int.from_bytes(encrypted_bytes[0:4], byteorder="little")
			decrypted_bytes_0 = ((encrypted_bytes_0 ^ ((key[3] << 0x10) & MAX_VALUE)) ^ (key[5] >> 0x10)) ^ key[0]

			# We invert the order to BIG ENDIAN
			decrypted_bytes_0_0 = decrypted_bytes_0 & MAX_BYTE_VALUE
			decrypted_bytes_0_1 = (decrypted_bytes_0 >> 0x8) & MAX_BYTE_VALUE
			decrypted_bytes_0_2 = (decrypted_bytes_0 >> 0x10) & MAX_BYTE_VALUE
			decrypted_bytes_0_3 = (decrypted_bytes_0 >> 0x18) & MAX_BYTE_VALUE

			# We append the bytes in BIG ENDIAN
			decrypted_bytes.append(decrypted_bytes_0_0)
			decrypted_bytes.append(decrypted_bytes_0_1)
			decrypted_bytes.append(decrypted_bytes_0_2)
			decrypted_bytes.append(decrypted_bytes_0_3)

			# Decryption of the second chunk of 4 bytes (LITTLE ENDIAN)
			encrypted_bytes_1 = int.from_bytes(encrypted_bytes[4:8], byteorder="little")
			decrypted_bytes_1 = ((encrypted_bytes_1 ^ ((key[5] << 0x10) & MAX_VALUE)) ^ (key[7] >> 0x10)) ^ key[2]

			# We invert the order to BIG ENDIAN
			decrypted_bytes_1_0 = decrypted_bytes_1 & MAX_BYTE_VALUE
			decrypted_bytes_1_1 = (decrypted_bytes_1 >> 0x8) & MAX_BYTE_VALUE
			decrypted_bytes_1_2 = (decrypted_bytes_1 >> 0x10) & MAX_BYTE_VALUE
			decrypted_bytes_1_3 = (decrypted_bytes_1 >> 0x18) & MAX_BYTE_VALUE

			# We append the bytes in BIG ENDIAN
			decrypted_bytes.append(decrypted_bytes_1_0)
			decrypted_bytes.append(decrypted_bytes_1_1)
			decrypted_bytes.append(decrypted_bytes_1_2)
			decrypted_bytes.append(decrypted_bytes_1_3)

			# Decryption of the third chunk of 4 bytes (LITTLE ENDIAN)
			encrypted_bytes_2 = int.from_bytes(encrypted_bytes[8:12], byteorder="little")
			decrypted_bytes_2 = ((encrypted_bytes_2 ^ ((key[7] << 0x10) & MAX_VALUE)) ^ (key[1] >> 0x10)) ^ key[4]

			# We invert the order to BIG ENDIAN
			decrypted_bytes_2_0 = decrypted_bytes_2 & MAX_BYTE_VALUE
			decrypted_bytes_2_1 = (decrypted_bytes_2 >> 0x8) & MAX_BYTE_VALUE
			decrypted_bytes_2_2 = (decrypted_bytes_2 >> 0x10) & MAX_BYTE_VALUE
			decrypted_bytes_2_3 = (decrypted_bytes_2 >> 0x18) & MAX_BYTE_VALUE

			# We append the bytes in BIG ENDIAN
			decrypted_bytes.append(decrypted_bytes_2_0)
			decrypted_bytes.append(decrypted_bytes_2_1)
			decrypted_bytes.append(decrypted_bytes_2_2)
			decrypted_bytes.append(decrypted_bytes_2_3)

			# Decryption of the fourth chunk of 4 bytes (LITTLE ENDIAN)
			encrypted_bytes_3 = int.from_bytes(encrypted_bytes[12:16], byteorder="little")
			decrypted_bytes_3 = ((encrypted_bytes_3 ^ ((key[1] << 0x10) & MAX_VALUE)) ^ (key[3] >> 0x10)) ^ key[6]

			# We invert the order to BIG ENDIAN
			decrypted_bytes_3_0 = decrypted_bytes_3 & MAX_BYTE_VALUE
			decrypted_bytes_3_1 = (decrypted_bytes_3 >> 0x8) & MAX_BYTE_VALUE
			decrypted_bytes_3_2 = (decrypted_bytes_3 >> 0x10) & MAX_BYTE_VALUE
			decrypted_bytes_3_3 = (decrypted_bytes_3 >> 0x18) & MAX_BYTE_VALUE

			# We append the bytes in BIG ENDIAN
			decrypted_bytes.append(decrypted_bytes_3_0)
			decrypted_bytes.append(decrypted_bytes_3_1)
			decrypted_bytes.append(decrypted_bytes_3_2)
			decrypted_bytes.append(decrypted_bytes_3_3)

			# Next chunk of 16 bytes
			encrypted_bytes = encrypted_file.read(0x10)

	save_decrypted_file(file, decrypted_bytes)

# Gets file from args
def get_file_from_args():
	if len(sys.argv) == 2:
		filename = sys.argv[1]
		if os.path.exists(filename):
			return filename

file = get_file_from_args()
if file:
	decrypt_file(file)
else:
	print("Please provide a file to decrypt")
