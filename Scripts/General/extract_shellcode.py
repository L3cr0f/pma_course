import sys
import os

def join_path(splitted_path):
	path = ""
	for element in splitted_path:
		path = path + element

	return path

def extract_shellcode(binary_path, offset, size):
	shellcode = bytearray()
	counter = 0
	with open(binary_path, "rb") as binary_file:
		binary_file.seek(offset)
		byte = binary_file.read(1)

		while(counter < size):
			shellcode.append(int.from_bytes(byte, byteorder="big"))
			byte = binary_file.read(1)
			counter = counter + 1

	print("[+] Shellcode successfully extracted")
	return shellcode

def save_shellcode(binary_path, decoded_bytes):
	shellcode_path = join_path(binary_path.split(".")[0:-1]) + ".bin"
	decoded_file = open(shellcode_path, "wb")
	decoded_file.write(decoded_bytes)

	print("[+] Shellcode successfully saved in the file: " + shellcode_path)

# Gets file path from args
def get_file_from_args():
	binary_path = sys.argv[1]
	if os.path.exists(binary_path):
		return binary_path

# Gets the offset from args
def get_offset_from_args():
	offset = sys.argv[2]
	if "0x" in offset:
		offset = int(offset, 16)
	elif str.isdigit(offset):
		offset = int(offset, 10)
	else:
		offset = None
	return offset

# Gets the size from args
def get_size_from_args():	
	size = sys.argv[3]
	if str.isdigit(size):
		size = int(size, 10)
	else:
		size = None
	return size

def usage():
	print("\nUsage:")
	print("\npython3 " + sys.argv[0] + " <binary file> <offset> <size>\n")
	print("<binary file>		path of binary file from which extract the shellcode")
	print("<offset>		offset where the shellcode is stored, can be specified as integer (4194304) or hexadecimal (0x400000) address")
	print("<size>			size of the shellcode\n")

if len(sys.argv) == 4:
	binary_path = get_file_from_args()
	offset = get_offset_from_args()
	size = get_size_from_args()

	if binary_path and offset and size:
		shellcode = extract_shellcode(binary_path, offset, size)
		save_shellcode(binary_path, shellcode)
	else:
		usage()
else:
	usage()