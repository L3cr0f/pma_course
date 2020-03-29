import sys
import os

def convert_utf16_to_stardard(unicode_field):
	shellcode_bytes = []

	# We remove the initial "%u" field and swap the values:
	# Example: "%ue589" -> 0x89 0xe5
	shellcode_bytes.append(int(unicode_field[2:][2:], 16))
	shellcode_bytes.append(int(unicode_field[2:][0:2], 16))

	return shellcode_bytes

def extract_shellcode(file_path):
	shellcode = bytearray()
	with open(file_path, "r") as utf16_shellcode:
		unicode_field = utf16_shellcode.read(6)

		while unicode_field and unicode_field != "\n":
			shellcode_bytes = convert_utf16_to_stardard(unicode_field)
			shellcode.append(shellcode_bytes[0])
			shellcode.append(shellcode_bytes[1])

			unicode_field = utf16_shellcode.read(6)


	print("[+] Shellcode successfully extracted")
	return shellcode


def join_path(splitted_path):
	path = ""
	for element in splitted_path:
		path = path + element

	return path

def save_shellcode(file_path, decoded_bytes):
	shellcode_path = join_path(file_path.split(".")[0:-1]) + ".bin"
	decoded_file = open(shellcode_path, "wb")
	decoded_file.write(decoded_bytes)

	print("[+] Shellcode successfully saved in the file: " + shellcode_path)

# Gets file path from args
def get_file_from_args():
	file_path = sys.argv[1]
	if os.path.exists(file_path):
		return file_path

def usage():
	print("\nUsage:")
	print("\n$ python3 " + sys.argv[0] + " <shellcode file>\n")
	print("<shellcode file>		path of shellcode file")

if len(sys.argv) == 2:
	file_path = get_file_from_args()
	if file_path:
		shellcode = extract_shellcode(file_path)
		save_shellcode(file_path, shellcode)
	else:
		usage()
else:
	usage()