from idautils import *
from idc import *

#Color the Calls and sub functions grey
heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
funcCalls = []
for current in heads:
	if (GetMnem(current) == "call" or "sub" in GetOpnd(current, 0)
		or GetOpnd(current, 0) == "offset StartAddress"):
		funcCalls.append(current)

print("Number of calls and sub functions: %d" % (len(funcCalls)))

for current in funcCalls:
	SetColor(current, CIC_ITEM, 0xb5b5b5)


#Color Anti-VM instructions red and print their location
heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
antiVM = []
for current in heads:
	if (GetMnem(current) == "sidt" or GetMnem(current) == "sgdt"
		or GetMnem(current) == "sldt" or GetMnem(current) == "smsw"
		or GetMnem(current) == "str" or GetMnem(current) == "in"
		or GetMnem(current) == "cpuid"):
		antiVM.append(current)

print("Number of potential Anti-VM instructions: %d" % (len(antiVM)))

for current in antiVM:
	print ("Anti-VM potential at %x" % current)
	SetColor(current, CIC_ITEM, 0x0000ff)


#Color anti-debugging measures purple and print their location
heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
antiDbg = []
for current in heads:
	if ((GetMnem(current) == "int" and (GetOpnd(current, 0) == "3" or GetOpnd(current, 0) == "2D")) or GetMnem(current) == "rdtsc" or GetMnem(current) == "icebp"):
		antiDbg.append(current)

print("Number of potential Anti-Debugging instructions: %d" % (len(antiDbg)))

for current in antiDbg:
	print("Anti-Debugging potential at %x" % current)
	SetColor(current, CIC_ITEM, 0xff00aa)


#Color push/ret combinations yellow as a shellcode
heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
push_ret = []
previous = 0
for current in heads:
	if (GetMnem(current) == "ret" and GetMnem(previous) == "push"):
		push_ret.append(current)
	previous = current

print("Number of push/ret instructions: %d" % (len(push_ret)))

for current in push_ret:
	SetColor(current, CIC_ITEM, 0x00ffff)


#Color non-zeroing out xor instructions green
heads = Heads(SegStart(ScreenEA()), SegEnd(ScreenEA()))
xor = []
for current in heads:
	if (GetMnem(current) == "xor"):
		if (GetOpnd(current,0) != GetOpnd(current,1)):
			xor.append(current)

print("Number of xor: %d" % (len(xor)))

for current in xor:
	SetColor(current, CIC_ITEM, 0x8fdf98)

