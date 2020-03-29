import os
import sys

hashes_1 = [
	0xEC0E4E8E,
	0xB8E579C1,
	0x78B5B983,
	0x7B8F17E6,
	0xE8AFE98,
	0x702F1A36
]

hashes_2 = [
	0xEC0E4E8E,
	0x16B3FE72,
	0x78B5B983,
	0x7B8F17E6
]

hashes_3 = [
	0x3BFCEDCB,
	0xADF509D9,
	0x60AAF9EC
]

hashes_4 = [
	0xEC0E4E8E,
	0x16B3FE72,
	0x78B5B983,
	0x7B8F17E6,
	0x5B8ACA33,
	0xBFC7034F,
	0x7C0017A5,
	0xDF7D9BAD,
	0x76DA08AC,
	0x10FA6516,
	0xE80A791F,
	0xFFD97FB,
	0xC0397EC,
	0x7CB922F6
]

hashes_5 = [
	0x1BE1BB5E
]


MAX_VALUE = 0xFFFFFFFF
INT_BITS = 32

# Left rotate of bits
def rotr(num, bits):
	return ((num >> bits)|(num << (INT_BITS - bits))) & MAX_VALUE

def get_hash(function_name):
	result = 0
	counter = 0
	while counter < len(function_name):
		result = (rotr(result, 0xD) + ord(function_name[counter])) & MAX_VALUE
		counter = counter + 1

	return result

def check_hash(function_name, hash_value):
	return get_hash(function_name) == hash_value

# Reads the file
def read_file(file):
	for hash_value in hashes_5:
		found = False
		with open(file, "r") as wordlist:
			function_name = wordlist.readline().rstrip('\n')
			while function_name and not found:
				found = check_hash(function_name, hash_value)
				if not found:
					function_name = wordlist.readline().rstrip('\n')

			if found:
				print("Occurrence found! The decrypted hash " + hex(hash_value) + " is: " + function_name)
			else:
				print("No occurrence found for hash " + hex(hash_value) + "!")

# Gets file from args
def get_file_from_args():
	if len(sys.argv) == 2:
		filename = sys.argv[1]
		if os.path.exists(filename):
			return filename

file = get_file_from_args()
if file:
	read_file(file)
else:
	print("Please provide a wordlist")