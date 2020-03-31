function_names = [
	"LoadLibraryA",
	"CreateProcessA",
	"TerminateProcess",
	"GetCurrentProcess",
	"GetTempPathA",
	"SetCurrentDirectoryA",
	"CreateFileA",
	"GetFileSize",
	"SetFilePointer",
	"ReadFile",
	"WriteFile",
	"CloseHandle",
	"GlobalAlloc",
	"GlobalFree",
	"ShellExecuteA"
]

def get_array_index(hexadecimal_index):
	return (int(hexadecimal_index, 16) / 4)

def get_function(address):

	hexadecimal_index = GetOpnd(address, 0)
	if "+" in hexadecimal_index:
		hexadecimal_index = hexadecimal_index.split("+")[1]
		if "h" in hexadecimal_index:
			hexadecimal_index = hexadecimal_index.split("h")[0]
		else:
			hexadecimal_index = hexadecimal_index[:-1]
	else:
		hexadecimal_index = "0"
	index = get_array_index(hexadecimal_index)
	return function_names[index]


heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
previous_address = 0

print("Adding function name as a comment...")

for current_address in heads:
	if (GetMnem(current_address) == "call" and "dword" in GetOpnd(current_address, 0)):
		MakeComm(current_address, get_function(current_address))

print("Functions added!")

