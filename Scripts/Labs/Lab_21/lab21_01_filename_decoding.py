MAX_VALUE_1 = 0xFF
MAX_VALUE_2 = 0xFFFFFFFF

def sar_32(byte, width):
	sign = byte & 0x80000000
	byte &= 0x7FFFFFFF
	byte >>= width
	byte |= sign
	return byte

def decode_filename(filename):
	name = ""
	extension = filename[3:]

	for counter in range(3):
		character = ord(filename[counter])
		constant = 0x4EC4EC4F

		character = (character & MAX_VALUE_1) - 0x61
		character = (character * character) & MAX_VALUE_2
		character = character - 0x5
		value = ((character * constant) & 0xFFFFFFFF00000000) >> 0x20

		value = sar_32(value, 3)
		aux_value = (value >> 0x1F) & MAX_VALUE_2
		value = (value + aux_value) & MAX_VALUE_2
		value = (value * 0x1A) & MAX_VALUE_2
		character = character - value 

		if character < 0:
			character = (character & MAX_VALUE_1) + 0x1A
		character = (character & MAX_VALUE_1) + 0x61

		name = name + chr(character)

	expected_filename = name + extension
	return expected_filename

filename = "ocl.exe"
expected_filename = decode_filename(filename)

print("The expected filename is: " + expected_filename)