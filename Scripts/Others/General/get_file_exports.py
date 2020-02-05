import sys
import pefile

file = pefile.PE(sys.argv[1])

print("######################")
print("EXPORTS")
print("######################")

for item in file.DIRECTORY_ENTRY_EXPORT.symbols:
	print(item.name.decode("UTF-8"))
