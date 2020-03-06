import os
import sys

HASH_VALUE = 0x0F30D12A5

def hash(process_name):
	result = 0
	counter = 0
	while (counter < 6) and (counter < len(process_name)):
		result = ((result << 5) | (result >> 0x1B)) + ord(process_name[counter])
		counter = counter + 1

	return result

def check_hash(process_name):
	return hash(process_name) == HASH_VALUE

# Reads the file
def read_file(file):
	found = False
	with open(file, "r") as wordlist:
		process_name = wordlist.readline()
		while process_name and not found:
			found = check_hash(process_name)
			if not found:
				process_name = wordlist.readline()

		if found:
			print("Occurrence found! The decrypted hash value is: " + process_name)
		else:
			print("No occurrence found!")

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
	print("Please provide a file to decrypt")