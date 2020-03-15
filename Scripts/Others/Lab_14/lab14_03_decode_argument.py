import sys

alphabet = "/abcdefghijklmnopqrstuvwxyz0123456789:."

def decode_argument(argument):
	decoded_argument = ""

	for i in range(0, len(argument), 2):
		arg_char = chr(ord(argument[i]) & 0xFF) + chr(ord(argument[i + 1]) & 0xFF)
		char_to_int = int(arg_char)
		decoded_char = alphabet[char_to_int]
		decoded_argument = decoded_argument + decoded_char

	print("The decoded argument is: " + decoded_argument)

if len(sys.argv) == 2:
	decode_argument(sys.argv[1])
else:
	print("Please provide the argument to decode")