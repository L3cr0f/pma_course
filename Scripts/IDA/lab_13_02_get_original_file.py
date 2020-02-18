from idautils import *
from idc import *
import os

def dump_buffer_to_file(address, size, filepath):
	data = GetManyBytes(address, size)
	with open(filepath, "wb") as file:
		file.write(data)
	print "Memdump Success!"

StartDebugger("","","")

# Address before the encryption routine
address = 0x0040187F

# Executes to address
RunTo(address)

# Waits the debugger
GetDebuggerEvent(WFNE_SUSP, -1);

# Get the value of the registers
buffer_address = GetRegValue('EAX')
bytes_to_write = GetRegValue('EDX')

desktop = os.path.join(os.environ["HOMEPATH"], "Desktop")
filepath = desktop +  "\\original_file.bmp"

# Dump file content
dump_buffer_to_file(buffer_address, bytes_to_write, filepath)