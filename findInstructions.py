from idautils import *
from idc import *
import re

GREG32 = ['eax','ebx','ecx']
AREG32 = GREG32 + ['ebp','esp']

GREG16 = ['eax','ebx','ecx']
AREG16 = GREG16 + ['ebp','esp']

GREG8 = ['eax','ebx','ecx']
AREG8 = GREG8 + ['ebp','esp']

str_find = 'mov %GREG32%, bl'
known_regs = {'GREG32X':'eax','GREG32X':'ebx'}

def findCodeSeqInFunction(ea):
	func_start_ea = get_func_attr(ea, FUNCATTR_START)
	func_end_ea = get_func_attr(ea, FUNCATTR_END)
	
	instructions_set = [x for x in Heads(func_start_ea,func_end_ea)]
	instructions_count = len(instructions_set)
	
	code_seq = str_find.split(";")
	for i, head in enumerate(instructions_set):
		if i < instructions_count-len(code_seq):
			found = True;
			for j, code in enumerate(code_seq):
				if codeMatches(instructions_set[i+j], code)[0]==False:
					found = False
					break
			if found:
				print "0x%X" % head , idc.generate_disasm_line(head,GENDSM_FORCE_CODE)
		
	print "next addr: 0x%X" % idc.next_head(here(),0x401059)

def codeMatches(ea, code):
	dis_asm = idc.generate_disasm_line(ea,GENDSM_FORCE_CODE)
	
	m = re.search('(?<=abc)def', 'abcdef')
	return False,True;

def replaceRegisters(code):
	result = ""
	matchs = re.finditer('%([^,]+?)%', code)
	for m in matchs:
		if known_regs != None:
			reg_str = m.group(1)
			
		else:
			result = code.replace(m.group(0),'(' + '|'.join(GREG32) + ')',1)
	return result

def getRegisterString(regString):
	r = known_regs.get(regString)
	if r == None:
		# it's not a known register
		m = re.match('(.)REG([0-9](?:[0-9])?)(.*)',regString)
	else
		return r


	
# findCodeSeqInFunction(here())
print replaceRegisters(str_find,kr)