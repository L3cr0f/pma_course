import sys
import pefile

file = pefile.PE(sys.argv[1])

print("######################")
print("IMPORTS")
print("######################")

for item in file.DIRECTORY_ENTRY_IMPORT:
	print("======================")
	print(item.dll.decode("UTF-8"))
	print("======================")
	for _import in item.imports:
		print(_import.name.decode("UTF-8"))
