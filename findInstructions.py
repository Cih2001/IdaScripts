from idautils import *
from idc import *
import re

class Register():
	TYPE8 = 0
	TYPE16 = 1
	TYPE32 = 2
	TYPE64 = 3

	TYPEA = 4

	GREG32 = ['eax','ebx','ecx']
	AREG32 = GREG32 + ['ebp','esp']

	GREG16 = ['ax','bx','cx']
	AREG16 = GREG16 + ['bp','sp']

	GREG8 = ['al','bl','cl' , 'ah', 'bh', 'ch']
	AREG8 = GREG8
	"""A simple attempt to model a car."""
	def __init__(self, str):
		"""Initialize car attributes."""
		self.type = 0
		self.name = ""
		self.replacement = ""
		self.group = []
		m = re.match('(.)REG([0-9](?:[0-9])?)(.*)',str)
		if m != None:
			if m.group(1) == 'A':
				self.type = self.type | TYPEA
			if m.group(2) == "8":
				self.type = self.type | TYPE8
				if self.type & TYPEA:
					self.group = AREG8
				else:
					self.group = GREG8
			if m.group(2) == "16":
				self.type = self.type | TYPE16
				if self.type & TYPEA:
					self.group = AREG16
				else:
					self.group = GREG16
			if m.group(2) == "32":
				self.type = self.type | TYPE32
				if self.type & TYPEA:
					self.group = AREG32
				else:
					self.group = GREG32
			if m.group(2) == "64":
				self.type = self.type | TYPE64
				if self.type & TYPEA:
					self.group = AREG64
				else:
					self.group = GREG64
			if m.group(3) != None:
				self.name = m.group(3)
	
	def toString(self):
		if self.replacement == "":
			return '(' + '|'.join(self.group) + ')'
		else:
			return self.replacement
	
	
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
		reg = Register(m.group(1))
		kr = known_regs.get(reg.name)
		if kr != None:
			result = code.replace(m.group(0),kr.toString(),1)
		else:
			if reg.name != "":
				known_regs[reg.name]=reg
			result = code.replace(m.group(0),reg.toString(),1)
			
	return result

str_find = 'mov %GREG32X%, bl'
known_regs = {'X':Register("GREG32X")}
# findCodeSeqInFunction(here())
print replaceRegisters(str_find)