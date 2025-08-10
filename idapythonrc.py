print('Running init script...')

import ida_loader
import ida_idaapi

try:
    get = get_name_ea_simple
except:
    pass

ida_idaapi.enable_extlang_python(True)
ida_idaapi.enable_python_cli(True)
ida_idaapi.set_script_timeout(5)

try:
    ida_loader.load_and_run_plugin("idapython", 3)
except Exception as ex:
    print(f"Failed to use load_and_run_plugin!: {ex}")

def get_byte(addr):
    return int.from_bytes([ida_dbg.get_dbg_byte(addr)], "little", signed=False)

def get_word(addr):
    bytes = []
    for i in range(addr, addr+1):
        bytes.append(ida_dbg.get_dbg_byte(i))
    return int.from_bytes(bytes, "little", signed=False)

def get_dword(addr):
    bytes = []
    for i in range(addr, addr+3):
        bytes.append(ida_dbg.get_dbg_byte(i))
    return int.from_bytes(bytes, "little", signed=False)

def get_qword(addr):
    bytes = []
    for i in range(addr, addr+7):
        bytes.append(ida_dbg.get_dbg_byte(i))
    return int.from_bytes(bytes, "little", signed=False)

def get_byte_signed(addr):
    return int.from_bytes([ida_dbg.get_dbg_byte(addr)], "little", signed=True)

def get_word_signed(addr):
    bytes = []
    for i in range(addr, addr+1):
        bytes.append(ida_dbg.get_dbg_byte(i))
    return int.from_bytes(bytes, "little", signed=True)

def get_dword_signed(addr):
    bytes = []
    for i in range(addr, addr+3):
        bytes.append(ida_dbg.get_dbg_byte(i))
    return int.from_bytes(bytes, "little", signed=True)

def get_qword_signed(addr):
    bytes = []
    for i in range(addr, addr+7):
        bytes.append(ida_dbg.get_dbg_byte(i))
    return int.from_bytes(bytes, "little", signed=True)

def get_string(addr, length = -1, strtype = 0):
    return ida_bytes.get_strlit_contents(addr, length, strtype)

def get_string_unicode(addr):
    string = ""
    while True:
        char = idc.get_wide_word(addr)
        if char == 0:
            break
        string += chr(char)
        addr += 2

    return string

def set_byte(addr, val):
    ida_dbg.put_dbg_byte(addr, (val).to_bytes(1, 'little', signed=False)[0])

def set_word(addr, val):
    bytes = (val).to_bytes(2, 'little', signed=False)
    i = 0
    for b in bytes:
        ida_dbg.put_dbg_byte(addr + i, b)
        i += 1

def set_dword(addr, val):
    bytes = (val).to_bytes(4, 'little', signed=False)
    i = 0
    for b in bytes:
        ida_dbg.put_dbg_byte(addr + i, b)
        i += 1

def set_qword(addr, val):
    bytes = (val).to_bytes(8, 'little', signed=False)
    i = 0
    for b in bytes:
        ida_dbg.put_dbg_byte(addr + i, b)
        i += 1

def set_byte_signed(addr, val):
    ida_dbg.put_dbg_byte(addr, (val).to_bytes(1, 'little', signed=True)[0])

def set_word_signed(addr, val):
    bytes = (val).to_bytes(2, 'little', signed=True)
    i = 0
    for b in bytes:
        ida_dbg.put_dbg_byte(addr + i, b)
        i += 1

def set_dword_signed(addr, val):
    bytes = (val).to_bytes(4, 'little', signed=True)
    i = 0
    for b in bytes:
        ida_dbg.put_dbg_byte(addr + i, b)
        i += 1

def set_qword_signed(addr, val):
    bytes = (val).to_bytes(8, 'little', signed=True)
    i = 0
    for b in bytes:
        ida_dbg.put_dbg_byte(addr + i, b)
        i += 1

read_byte = get_byte
read_word = get_word
read_dword = get_dword
read_qword = get_qword
read_byte_signed = get_byte_signed
read_word_signed = get_word_signed
read_dword_signed = get_dword_signed
read_qword_signed = get_qword_signed
read_string = get_string
read_string_unicode = get_string_unicode
get_unicode_string = get_string_unicode
read_unicode_string = get_string_unicode

write_byte = set_byte
write_word = set_word
write_dword = set_dword
write_qword = set_qword
write_byte_signed = set_byte_signed
write_word_signed = set_word_signed
write_dword_signed = set_dword_signed
write_qword_signed = set_qword_signed

def arg(i):
  if i == 1:
    return ida_dbg.get_reg_val('rcx')
  if i == 2:
    return ida_dbg.get_reg_val('rdx')
  if i == 3:
    return ida_dbg.get_reg_val('r8')
  if i == 4:
    return ida_dbg.get_reg_val('r9')

def eax(val=None):
    if val == None:
        return ida_dbg.get_reg_val('eax')
    else:
        ida_dbg.set_reg_val('eax', val)

def rax(val=None):
    if val == None:
        return ida_dbg.get_reg_val('rax')
    else:
        ida_dbg.set_reg_val('rax', val)

def ebx(val=None):
    if val == None:
        return ida_dbg.get_reg_val('ebx')
    else:
        ida_dbg.set_reg_val('ebx', val)

def rbx(val=None):
    if val == None:
        return ida_dbg.get_reg_val('rbx')
    else:
        ida_dbg.set_reg_val('rbx', val)

def ecx(val=None):
    if val == None:
        return ida_dbg.get_reg_val('ecx')
    else:
        ida_dbg.set_reg_val('ecx', val)

def rcx(val=None):
    if val == None:
        return ida_dbg.get_reg_val('rcx')
    else:
        ida_dbg.set_reg_val('rcx', val)

def edx(val=None):
    if val == None:
        return ida_dbg.get_reg_val('edx')
    else:
        ida_dbg.set_reg_val('edx', val)

def rdx(val=None):
    if val == None:
        return ida_dbg.get_reg_val('rdx')
    else:
        ida_dbg.set_reg_val('rdx', val)

def esi(val=None):
    if val == None:
        return ida_dbg.get_reg_val('esi')
    else:
        ida_dbg.set_reg_val('esi', val)

def rsi(val=None):
    if val == None:
        return ida_dbg.get_reg_val('rsi')
    else:
        ida_dbg.set_reg_val('rsi', val)

def edi(val=None):
    if val == None:
        return ida_dbg.get_reg_val('edi')
    else:
        ida_dbg.set_reg_val('edi', val)

def rdi(val=None):
    if val == None:
        return ida_dbg.get_reg_val('rdi')
    else:
        ida_dbg.set_reg_val('rdi', val)

def r8(val=None):
    if val == None:
        return ida_dbg.get_reg_val('r8')
    else:
        ida_dbg.set_reg_val('r8', val)

def r9(val=None):
    if val == None:
        return ida_dbg.get_reg_val('r9')
    else:
        ida_dbg.set_reg_val('r9', val)

def r10(val=None):
    if val == None:
        return ida_dbg.get_reg_val('r10')
    else:
        ida_dbg.set_reg_val('r10', val)

def r11(val=None):
    if val == None:
        return ida_dbg.get_reg_val('r11')
    else:
        ida_dbg.set_reg_val('r11', val)

def r12(val=None):
    if val == None:
        return ida_dbg.get_reg_val('r12')
    else:
        ida_dbg.set_reg_val('r12', val)

def r13(val=None):
    if val == None:
        return ida_dbg.get_reg_val('r13')
    else:
        ida_dbg.set_reg_val('r13', val)

def r14(val=None):
    if val == None:
        return ida_dbg.get_reg_val('r14')
    else:
        ida_dbg.set_reg_val('r14', val)

def r15(val=None):
    if val == None:
        return ida_dbg.get_reg_val('r15')
    else:
        ida_dbg.set_reg_val('r15', val)

def zf(val=None):
    if val == None:
        return ida_dbg.get_reg_val('zf')
    else:
        ida_dbg.set_reg_val('zf', val)

def ebp(val=None):
    if val == None:
        return ida_dbg.get_reg_val('ebp')
    else:
        ida_dbg.set_reg_val('ebp', val)

def esp(val=None):
    if val == None:
        return ida_dbg.get_reg_val('esp')
    else:
        ida_dbg.set_reg_val('esp', val)

def rip(val=None):
    if val == None:
        return ida_dbg.get_reg_val('rip')
    else:
        ida_dbg.set_reg_val('rip', val)

def rbp(val=None):
    if val == None:
        return ida_dbg.get_reg_val('rbp')
    else:
        ida_dbg.set_reg_val('rbp', val)

def rsp(val=None):
    if val == None:
        return ida_dbg.get_reg_val('rsp')
    else:
        ida_dbg.set_reg_val('rsp', val)

def al(val=None):
    if val == None:
        return ida_dbg.get_reg_val('al')
    else:
        ida_dbg.set_reg_val('al', val)

def toSigned32(n):
    n = n & 0xffffffff
    return (n ^ 0x80000000) - 0x80000000


def findUnfoundFunctions():
    # Very much WIP, probably not safe to run on an IDA DB that you care about...
    #_, start, end = idaapi.read_range_selection(None)
    currentEA = idaapi.get_screen_ea()
    ea = currentEA
    currentSeg = ida_segment.getseg(currentEA)
    endOfSeg = currentSeg.end_ea
    newFuncStarts = []

    print(f"Start: {hex(currentEA)}")

    while ea < endOfSeg and ea < currentEA + 0x10000:
        if ida_funcs.get_func(ea) is None:
            if idaapi.get_byte(ea) == 0xcc:
                pass
            elif idaapi.get_byte(ea) == 0x90:
                pass
            elif not ida_bytes.is_unknown(ida_bytes.get_flags(ea)):
                pass
            else:
                newFuncStarts.append(ea)
                print(f"New Func?: {hex(ea)}")
                idc.create_insn(ea)
                ida_funcs.add_func(ea)
                #insn = idaapi.insn_t()
                #length = idaapi.decode_insn(insn, ea)
                #print(f"    insn:{insn}, length:{hex(length)}")
        ea += 1

    if newFuncStarts is not None and len(newFuncStarts) > 0:
        print(f"Created {len(newFuncStarts)} new functions!")
        jumpto(ea)
    else:
        print(f"No new function created")
        jumpto(ea)

    print(f"Remaining bytes: {hex(endOfSeg - ea)}")

# class obj:
#     """Defines an obj, which enables you to more easily inspect and manipulate structs"""
#     address = 0
#     name = ''
#     strucType = None
#
#     def __init__(self, arg1, arg2=None, arg3=None):
#         if arg2 == None:
#             if isinstance(arg1, str):
#                 self.name = arg1
#                 self.address = get_name_ea_simple(arg1)
#             elif isinstance(arg1, int):
#                 self.name = hex(arg1)
#                 self.address = arg1
#         else:
#             if isinstance(arg1, str):
#                 self.name = arg1
#                 self.address = arg2
#             elif isinstance(arg1, int):
#                 self.name = arg2
#                 self.address = arg1
#         if arg3 != None:
#             self.strucType = arg3
#         else:
#             self.strucType = get_type(self.address)
#
#     def __getattr__(self, index):
#         if isinstance(index, int):
#             newName = self.name + '[{}]'.format(hex(index))
#             newAddress = self.address + index
#             child = obj(newName, newAddress)
#             # print('Getting {} + {} = {} of "{}": {} value -> {}'.format(hex(self.address), hex(index), hex(newAddress), self.name, newName, hex(child.qword())))
#             # print("returning child: {}".format(child))
#             return child
#         elif isinstance(index, str):
#             if self.strucType == None:
#                 print("Can't get attribute '{}' by name for unTyped object '{}'".format(index, self.name))
#                 return self
#
#             strucName = self.strucType.removesuffix(' *')
#             strucId = idaapi.get_struc_id(strucName)
#
#             if strucId == -1:
#                 print("Failed to find struc_id for struc '{}'".format(strucName))
#                 return self
#
#             struc = idaapi.get_struc(strucId)
#             if struc == None:
#                 print("Failed to find struc by id {}".format(strucId))
#                 return self
#
#             member = idaapi.get_member_by_name(struc, index)
#             if member == None:
#                 print("Failed to find member '{}' of struc '{}'".format(index, strucName))
#                 return self
#
#             newName = self.name + '.' + index
#             newAddress = self.address + member.soff
#             #print(dir(member))
#             #print("Accessing member '{}' at address {}".format(newName, hex(newAddress)))
#             memberObj = obj(newName, newAddress)
#             memberObj.strucType = index
#             # return member
#             return memberObj
#
#     def __str__(self):
#         return '{}({}) of type {}'.format(self.name, hex(self.address), self.strucType)
#
#     def __getitem__(self, index):
#         return self.__getattr__(index)
#
#     def byte(self, offset=0):
#         return ida_bytes.get_byte(self.address + offset)
#
#     def word(self, offset=0):
#         return ida_bytes.get_word(self.address + offset)
#
#     def dword(self, offset=0):
#         return ida_bytes.get_dword(self.address + offset)
#
#     def qword(self, offset=0):
#         return ida_bytes.get_qword(self.address + offset)
#
#     def asType(self, typeName):
#         self.strucType = typeName
#         return self
#
#     def offset(self, index):
#         newName = '({} + {})'.format(self.name, hex(index))
#         newAddress = self.address + index
#         child = obj(newName, newAddress)
#         return child
#
#     def deref(self):
#         newAddress = self.qword()
#         # print('Dereferencing "{}" ({}) to {}'.format(self.name, hex(self.address), hex(newAddress)))
#         child = obj(self.name + '->', newAddress)
#         child.strucType = self.strucType.removesuffix(' *')
#         return child

# gameData = obj('gameData').deref()
# print('version from offset: {}'.format(gameData[0x400].byte()))
# print('Version from member: {}'.format(gameData.version.byte()))

print('Initialization finished!')