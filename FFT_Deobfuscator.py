from idaapi import PluginForm
from PyQt5 import QtCore, QtGui, QtWidgets
import PySide6
import ida_domain, ida_bytes, idaapi, idc, ida_allins, ida_kernwin
from ida_domain import operands

OperandType = operands.OperandType

four_byte_regs = ['r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d', 'esi', 'edi', 'eax', 'ebx', 'ecx', 'edx', 'ebp']

db = ida_domain.Database()

class DeobfuscatorWizard(QtWidgets.QWidget):
    def __init__(self):
        super(DeobfuscatorWizard, self).__init__()
        
        self.ea = 0x0
        self.instructions = []
        self.register = 'ecx'
        self.result = 0
        self.patch_bytes = b''
        
        self.layout = QtWidgets.QVBoxLayout()

        self.header_row = QtWidgets.QHBoxLayout()
        self.goto_selected_button = QtWidgets.QPushButton("Selected")
        self.goto_selected_button.clicked.connect(self.goto_selected)
        self.goto_address_button = QtWidgets.QPushButton("Goto")
        self.goto_address_button.clicked.connect(self.goto_address)
        self.header_address_edit = QtWidgets.QLineEdit(hex(idc.here()))
        self.next_obfuscation_button = QtWidgets.QPushButton("Next")
        self.next_obfuscation_button.clicked.connect(self.goto_next)
        self.next_obfuscation_button = QtWidgets.QPushButton("Next")
        self.next_obfuscation_button.clicked.connect(self.goto_next)
        self.follow_checkbox = QtWidgets.QCheckBox("Follow Cursor")
        self.follow_checkbox.setChecked(True)
        self.auto_deobfuscate_checkbox = QtWidgets.QCheckBox("Auto Deobfuscate")
        self.auto_deobfuscate_checkbox.setChecked(False)
        self.header_row.addWidget(self.goto_selected_button)
        self.header_row.addWidget(self.goto_address_button)
        self.header_row.addWidget(self.header_address_edit)
        self.header_row.addWidget(self.next_obfuscation_button)
        self.header_row.addWidget(self.follow_checkbox)
        self.header_row.addWidget(self.auto_deobfuscate_checkbox)
        
        self.instruction1_row = QtWidgets.QHBoxLayout()
        self.instruction1_type = QtWidgets.QLineEdit('mov')
        self.instruction1_type.setMaximumWidth(50)
        self.instruction1_op1 = QtWidgets.QLineEdit('eax')
        self.instruction1_op1.setMaximumWidth(100)
        self.instruction1_op2 = QtWidgets.QLineEdit('dword_12345678')
        self.instruction1_value = QtWidgets.QLineEdit('0x4cd3f818')
        self.instruction1_row.addWidget(self.instruction1_type)
        self.instruction1_row.addWidget(self.instruction1_op1)
        self.instruction1_row.addWidget(self.instruction1_op2)
        self.instruction1_row.addWidget(self.instruction1_value)
        
        self.instruction2_row = QtWidgets.QHBoxLayout()
        self.instruction2_type = QtWidgets.QLineEdit('add')
        self.instruction2_type.setMaximumWidth(50)
        self.instruction2_op1 = QtWidgets.QLineEdit('eax')
        self.instruction2_op1.setMaximumWidth(100)
        self.instruction2_op2 = QtWidgets.QLineEdit('12345678')
        self.instruction2_value = QtWidgets.QLineEdit('0x4cd3f818')
        self.instruction2_row.addWidget(self.instruction2_type)
        self.instruction2_row.addWidget(self.instruction2_op1)
        self.instruction2_row.addWidget(self.instruction2_op2)
        self.instruction2_row.addWidget(self.instruction2_value)
        
        self.instruction3_row = QtWidgets.QHBoxLayout()
        self.instruction3_type = QtWidgets.QLineEdit('mov')
        self.instruction3_type.setMaximumWidth(50)
        self.instruction3_op1 = QtWidgets.QLineEdit('eax')
        self.instruction3_op1.setMaximumWidth(100)
        self.instruction3_op2 = QtWidgets.QLineEdit('dword_12345678')
        self.instruction3_value = QtWidgets.QLineEdit('0x4cd3f818')
        self.instruction3_row.addWidget(self.instruction3_type)
        self.instruction3_row.addWidget(self.instruction3_op1)
        self.instruction3_row.addWidget(self.instruction3_op2)
        self.instruction3_row.addWidget(self.instruction3_value)
        
        self.result_row = QtWidgets.QHBoxLayout()
        self.result_label = QtWidgets.QLabel("Result:")
        self.result_edit = QtWidgets.QLineEdit('0x04')
        self.generate_button = QtWidgets.QPushButton("Generate")
        self.generate_button.clicked.connect(self.preview)
        #self.patch_button = QtWidgets.QPushButton("Patch")
        #self.patch_button.clicked.connect(self.patch)
        self.result_row.addWidget(self.result_label)
        self.result_row.addWidget(self.result_edit)
        self.result_row.addWidget(self.generate_button)
        #self.result_row.addWidget(self.patch_button)
        
        self.patch_row = QtWidgets.QHBoxLayout()
        self.patch_label = QtWidgets.QLabel("Patch:")
        self.patch_edit = QtWidgets.QLineEdit('')
        #self.preview_button = QtWidgets.QPushButton("Preview")
        #self.preview_button.clicked.connect(self.preview)
        self.patch_button = QtWidgets.QPushButton("Patch")
        self.patch_button.clicked.connect(self.patch)

        self.patch_all_button = QtWidgets.QPushButton("Patch All")
        self.patch_all_button.clicked.connect(self.patch_all)

        self.patch_row.addWidget(self.patch_label)
        self.patch_row.addWidget(self.patch_edit)
        #self.patch_row.addWidget(self.preview_button)
        self.patch_row.addWidget(self.patch_button)
        self.patch_row.addWidget(self.patch_all_button)

        #self.bottom_layout = QtWidgets.QVBoxLayout()
        #self.bottom_spacer = QtWidgets.QSpacerItem(0, 0, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        #self.bottom_layout.addWidget(self.bottom_spacer)

        # self.patch_group = QtWidgets.QVBoxLayout()
        # self.patch_widget = QtWidgets.QWidget()
        # # self.patch_widget.setSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        # self.patch_widget.setLayout(self.patch_group)
        #
        # self.layout.addLayout(self.header_row)
        # self.layout.addWidget(self.patch_widget, 0, QtCore.Qt.AlignmentFlag.AlignTop)
        # # self.layout.addStretch(0)
        # self.patch_group.addLayout(self.instruction1_row)
        # self.patch_group.addLayout(self.instruction2_row)
        # self.patch_group.addLayout(self.instruction3_row)
        # self.patch_group.addLayout(self.result_row)
        # self.patch_group.addLayout(self.patch_row)
        # self.patch_group.addStretch(0)

        # self.patch_widget.hide()

        self.layout.addLayout(self.header_row)
        self.layout.addLayout(self.instruction1_row)
        self.layout.addLayout(self.instruction2_row)
        self.layout.addLayout(self.instruction3_row)
        self.layout.addLayout(self.result_row)
        self.layout.addLayout(self.patch_row)
        self.layout.addStretch(0)

        #self.parent.setLayout(layout)
        #self.name_box.setFocus()
        self.setLayout(self.layout)
        #self.show()
        # self.goto_address()

    def closeEvent(self, a):
        print('QWindow.close')
    
    def clear_instructions(self):
        self.instruction1_type.setText('')
        self.instruction1_op1.setText('')
        self.instruction1_op2.setText('')
        self.instruction1_value.setText('')
        
        self.instruction2_type.setText('')
        self.instruction2_op1.setText('')
        self.instruction2_op2.setText('')
        self.instruction2_value.setText('')
        
        self.instruction3_type.setText('')
        self.instruction3_op1.setText('')
        self.instruction3_op2.setText('')
        self.instruction3_value.setText('')

        self.result_edit.setText('')

        self.instructions = []
        self.register = 'ecx'
        self.result = 0
        self.patch_bytes = b''

        self.hide_body()

        # for w in (self.instruction2_row.itemAt(i) for i in range(self.instruction2_row.count())): w.widget().hide()
        # for w in (self.instruction3_row.itemAt(i) for i in range(self.instruction3_row.count())): w.widget().hide()
        # for w in (self.instruction1_row.itemAt(i) for i in range(self.result_row.count())): w.widget().hide()
        # for w in (self.instruction2_row.itemAt(i) for i in range(self.instruction2_row.count())): w.widget().hide()

    def hide_body(self):
        for layout in [self.instruction1_row, self.instruction2_row, self.instruction3_row, self.result_row, self.patch_row]:
            for w in (layout.itemAt(i) for i in range(layout.count())): w.widget().hide()

    def show_body(self):
        for layout in [self.instruction1_row, self.instruction2_row, self.instruction3_row, self.result_row, self.patch_row]:
            for w in (layout.itemAt(i) for i in range(layout.count())): w.widget().show()

    def goto_selected(self):
        address = idc.here()
        self.header_address_edit.setText(hex(address))
        # print(f'goto: {hex(address)}')
        self.read_obfuscation(address)

    def goto_address(self, address = None):
        if address is not None:
            self.header_address_edit.setText(hex(address))
        else:
            address = int(self.header_address_edit.text(), 0)
        # print(f'goto: {hex(address)}')
        self.read_obfuscation(address)
        if self.auto_deobfuscate_checkbox.isChecked():
            self.patch()
    
    def goto_next(self):
        obfuscations = find_obfuscations_in_function(self.ea)
        if len(obfuscations) > 0:
            next_obfuscation = obfuscations[0][1][0].ea
            print(f'Next Obfuscation: {hex(next_obfuscation)}')
            self.goto_address(next_obfuscation)
        else:
            print('No remaining Obfuscations')
            self.clear_instructions()

        
    def get_operand_value(self, op):
        value = 0
        if op.type == OperandType.MEMORY:
            value = ida_bytes.get_dword(op.get_address())
        elif op.type == OperandType.IMMEDIATE:
            value = op.get_value() & 0xffffffff
        return value
    
    def get_opcode_name(self, instruction):
        if instruction == ida_allins.NN_sub:
            return 'sub'
        elif instruction == ida_allins.NN_add:
            return 'add'
        elif instruction == ida_allins.NN_xor:
            return 'xor'
        else:
            return 'unknown'
    
    def read_obfuscation(self, ea):
        self.hide_body()
        self.ea = ea
        # print(f'Checking {hex(ea)} for obfuscations...')
        insn1 = db.instructions.get_at(ea)
        i1o1 = ida_domain.operands.OperandFactory.create(db, insn1.Op1, insn1)
        i1o2 = ida_domain.operands.OperandFactory.create(db, insn1.Op2, insn1)

        if not check_for_obfuscation(ea):
            # print(f'Failed new obfuscation check at: {hex(ea)}')
            self.clear_instructions()
            return

        if not (insn1.itype == ida_allins.NN_mov and i1o1.type == OperandType.REGISTER and (i1o2.type == OperandType.REGISTER or i1o2.type == OperandType.IMMEDIATE or i1o2.type == OperandType.MEMORY)):
            # print('No obfuscation identified.')
            self.clear_instructions()
            return
        
        # print('Obfuscation possible...')
        
        result = 0
        
        self.clear_instructions()
        self.instructions.append(insn1)
        self.instruction1_type.setText('mov')
        self.instruction1_op1.setText(i1o1.get_register_name())
        self.register = i1o1.get_register_name()
        if i1o2.type == OperandType.IMMEDIATE:
            result = i1o2.get_value()
            if self.register in four_byte_regs: result = result & 0xffffffff
            self.instruction1_op2.setText(hex(result))
            self.instruction1_value.setText(hex(result))
        elif i1o2.type == OperandType.MEMORY:
            self.instruction1_op2.setText(i1o2.get_name())
            result = ida_bytes.get_dword(i1o2.get_value())
            if self.register in four_byte_regs: result = result & 0xffffffff
            self.instruction1_value.setText(hex(result))
        
        insn2 = db.instructions.get_at(insn1.ea + insn1.size)
        self.instructions.append(insn2)
        i2o1 = ida_domain.operands.OperandFactory.create(db, insn2.Op1, insn2)
        i2o2 = ida_domain.operands.OperandFactory.create(db, insn2.Op2, insn2)

        if i2o1 == None:
            return
        
        if i2o1.type == OperandType.REGISTER and i2o1.get_register_name() == i1o1.get_register_name():
            self.instruction2_type.setText(self.get_opcode_name(insn2.itype))
        else:
            self.clear_instructions()
            # print(f'Instruction 2 Operand 1 is not Register. Not obfuscated.')
            return
        self.instruction2_op1.setText(i2o1.get_register_name())
        
        if i2o2.type == OperandType.IMMEDIATE:
            insn2_value = i2o2.get_value()
            if self.register in four_byte_regs: insn2_value = insn2_value & 0xffffffff
            self.instruction2_op2.setText(hex(insn2_value))
            self.instruction2_value.setText(hex(insn2_value))
        elif i2o2.type == OperandType.MEMORY:
            # print(f'i2o2: {i2o2}, {i2o2.get_name()}, {i2o2.get_value()}')
            self.instruction2_op2.setText(i2o2.get_name())
            insn2_value = ida_bytes.get_dword(i2o2.get_value())
            if self.register in four_byte_regs: insn2_value = insn2_value & 0xffffffff
            self.instruction2_value.setText(hex(insn2_value))
        elif i2o2.type == OperandType.REGISTER:
            self.clear_instructions()
            return
        
        if insn2.itype == ida_allins.NN_add:
            result = result + insn2_value
        elif insn2.itype == ida_allins.NN_sub:
            result = result - insn2_value
        elif insn2.itype == ida_allins.NN_xor:
            result = result ^ insn2_value
        
        insn3 = db.instructions.get_at(insn2.ea + insn2.size)
        i3o1 = ida_domain.operands.OperandFactory.create(db, insn3.Op1, insn3)
        i3o2 = ida_domain.operands.OperandFactory.create(db, insn3.Op2, insn3)

        if (insn3 is not None
                and insn3.itype != ida_allins.NN_shl
                and insn3.itype != ida_allins.NN_shr
                and insn3.itype != ida_allins.NN_cmp
                and i3o1 is not None
                and i3o1.type == OperandType.REGISTER
                and (i3o1.type == OperandType.IMMEDIATE or i3o1.type == OperandType.MEMORY)
                and i3o1.get_register_name() == i1o1.get_register_name()):
            self.instructions.append(insn3)
            self.instruction3_type.setText(self.get_opcode_name(insn3.itype))
            self.instruction3_op1.setText(i3o1.get_register_name())
            if i3o2.type == OperandType.IMMEDIATE:
                insn3_value = i3o2.get_value()
                if self.register in four_byte_regs: insn3_value = insn3_value & 0xffffffff
                self.instruction3_op2.setText(hex(i3o2.get_value() & 0xffffffff))
                self.instruction3_value.setText(hex(i3o2.get_value() & 0xffffffff))
                if insn3.itype == ida_allins.NN_add:
                    result = result + insn3_value
                elif insn3.itype == ida_allins.NN_sub:
                    result = result - insn3_value
                elif insn3.itype == ida_allins.NN_xor:
                    result = result ^ insn3_value
            elif i3o2.type == OperandType.MEMORY:
                insn3_value = ida_bytes.get_dword(i3o2.get_value())
                if self.register in four_byte_regs: insn3_value = insn3_value & 0xffffffff
                self.instruction3_op2.setText(i3o2.get_name())
                self.instruction3_value.setText(hex(ida_bytes.get_dword(i3o2.get_value()) & 0xffffffff))
                if insn3.itype == ida_allins.NN_add:
                    result = result + insn3_value
                elif insn3.itype == ida_allins.NN_sub:
                    result = result - insn3_value
                elif insn3.itype == ida_allins.NN_xor:
                    result = result ^ insn3_value
        if self.register in four_byte_regs: result = result & 0xffffffff
        self.result_edit.setText(hex(result))
        self.result = result
        self.show_body()
        self.preview()
    
    def preview(self):
        self.result = int(self.result_edit.text(), 0)
        # print(f'{self.result_edit.text()}')
        patch_text, self.patch_bytes = generate_patch(self.instructions, self.register, self.result)
        # print(f'Patch_bytes: {self.patch_bytes}')
        self.patch_edit.setText(f'{patch_text}')
        # if self.auto_deobfuscate_checkbox.isChecked():
        #     print(f'Auto deobfuscating...')
        #     apply_patch(self.ea, self.patch_bytes)
        
    def patch(self):
        #patch_obfuscation(self.instructions, self.register, self.result, False)
        # print(f'patch: {hex(self.ea)}: {self.patch_bytes}')
        apply_patch(self.ea, self.patch_bytes)
        self.goto_next()

    def patch_all(self):
        limit = 30
        self.goto_next()
        while limit > 0 and self.patch_bytes != b'':
            limit = limit - 1
            apply_patch(self.ea, self.patch_bytes)
            self.goto_next()
    
    def OnClose(self, form):
        pass

class DeobfuscatorPluginForm(PluginForm):
    def __init__(self):
        super().__init__()
        self.deobfuscatorWizard = DeobfuscatorWizard()
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def OnClose(self, form):
        print('Closing...')
    
    def PopulateForm(self):
        # self.deobfuscatorWizard = DeobfuscatorWizard()
        self.widget2 = QtWidgets.QWidget()
    
        self.layout = QtWidgets.QVBoxLayout()
        
        self.page_layout = QtWidgets.QHBoxLayout()
        
        #self.layout.addLayout(self.page_layout)

        self.widget_1_button = QtWidgets.QPushButton('Deobfuscator')
        self.widget_1_button.clicked.connect(self.showPanel1)
        self.page_layout.addWidget(self.widget_1_button)
        
        self.widget_2_button = QtWidgets.QPushButton('Widget2')
        self.widget_2_button.clicked.connect(self.showPanel2)
        #self.page_layout.addWidget(self.widget_2_button)
        
        self.stack = QtWidgets.QStackedWidget()
        self.stack.addWidget(self.deobfuscatorWizard)
        self.stack.addWidget(self.widget2)
        self.layout.addWidget(self.stack)
        self.parent.setLayout(self.layout)
        self.stack.setCurrentIndex(0)
        self.statusBar = QtWidgets.QStatusBar()
        #self.layout.addWidget(self.statusBar)
        self.statusBar.showMessage("Ready", 2000)
    
    def showPanel1(self):
        self.stack.setCurrentIndex(0)
    
    def showPanel2(self):
        self.stack.setCurrentIndex(1)
    
    def OnClose(self, form):
        pass

def generate_patch(instructions, reg, result):
    try:
        print_debug = False
        if not check_for_obfuscation(instructions[0].ea):
            # print(f'Failed new obfuscation check at: {hex(instructions[0].ea)}')
            return None, None

        total_size = 0
        if print_debug: print(f'{len(instructions)} instructions')
        for i in instructions:
            # print(f'Instruction {i.size} {i}')
            total_size = total_size + i.size
        if print_debug: print(f'Total size: {total_size}')
        i1o1 = ida_domain.operands.OperandFactory.create(db, instructions[0].Op1, instructions[0])
        asm_bytes = b''
        if reg == 'r8d':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\x41\xB8' + (result).to_bytes(4, 'little')
            if print_debug: print(f'asm bytes: {asm_bytes}')
            #41 B8 00 00 00 00
        elif reg == 'r9d':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\x41\xB9' + (result).to_bytes(4, 'little')
            if print_debug: print(f'asm bytes: {asm_bytes}')
            #41 B9 00 00 00 00
        elif reg == 'r10d':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\x41\xBA' + (result).to_bytes(4, 'little')
            if print_debug: print(f'asm bytes: {asm_bytes}')
            #41 BA 00 00 00 00
        elif reg == 'r11d':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\x41\xBB' + (result).to_bytes(4, 'little')
            if print_debug: print(f'asm bytes: {asm_bytes}')
            #41 BB 00 00 00 00
        elif reg == 'r12d':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\x41\xBC' + (result).to_bytes(4, 'little')
            if print_debug: print(f'asm bytes: {asm_bytes}')
        elif reg == 'r13d':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\x41\xBD' + (result).to_bytes(4, 'little')
            if print_debug: print(f'asm bytes: {asm_bytes}')
            #41 BD 1D 00 00 00
        elif reg == 'r14d':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\x41\xBE' + (result).to_bytes(4, 'little')
            if print_debug: print(f'asm bytes: {asm_bytes}')
        elif reg == 'r15d':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\x41\xBF' + (result).to_bytes(4, 'little')
            if print_debug: print(f'asm bytes: {asm_bytes}')
            #41 BF 00 00 00 00
        elif reg == 'eax':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\xB8' + ((result).to_bytes(8, 'little', signed=True)[0:4])
            if print_debug: print(f'asm bytes: {asm_bytes}')
            # B8 00 00 00 00
        elif reg == 'ecx':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\xB9' + ((result).to_bytes(8, 'little', signed=True)[0:4])
            if print_debug: print(f'asm bytes: {asm_bytes}')
            # B9 00 00 00 00
        elif reg == 'edx':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\xBA' + ((result).to_bytes(8, 'little', signed=True)[0:4])
            if print_debug: print(f'asm bytes: {asm_bytes}')
            # BA 00 00 00 00
        elif reg == 'ebx':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\xBB' + ((result).to_bytes(8, 'little', signed=True)[0:4])
            if print_debug: print(f'asm bytes: {asm_bytes}')
            # BB 00 00 00 00
        elif reg == 'ebp':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\xBD' + ((result).to_bytes(8, 'little', signed=True)[0:4])
            if print_debug: print(f'asm bytes: {asm_bytes}')
            # BD 00 00 00 00
        elif reg == 'esi':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\xBE' + ((result).to_bytes(8, 'little', signed=True)[0:4])
            if print_debug: print(f'asm bytes: {asm_bytes}')
            # BE 00 00 00 00
        elif reg == 'edi':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\xBF' + (result).to_bytes(4, 'little')
            if print_debug: print(f'asm bytes: {asm_bytes}')
            # BF 00 00 00 00
        elif reg == 'rsi':
            asm = f'mov {reg}, {result:04x}h'
            asm_bytes = b'\x48\xC7\xC6' + (result).to_bytes(4, 'little')
            # print(f'asm bytes: {asm_bytes}')
            if print_debug: print(f'Avoiding generating patch for rsi modification \'{asm}\'')
            return asm, None
            # 48 C7 C6 08 00 00 00
        else:
            if i1o1.size_bytes == 1:
                asm = f'mov {reg}, {result:02x}h'
            elif i1o1.size_bytes == 2:
                asm = f'mov {reg}, {result:04x}h'
            elif i1o1.size_bytes == 4:
                asm = f'mov {reg}, {result:08x}h'
            elif i1o1.size_bytes == 8:
                asm = f'mov {reg}, {result:16x}h'
            asm_bytes = ida_idp.AssembleLine(instructions[0].ea, 0, instructions[0].ea, True, asm)
            if print_debug: print(f"   ida_idp.AssembleLine({hex(instructions[0].ea)}, 0, {hex(instructions[0].ea)}, True, '{asm}')")
        if asm_bytes == None:
            if print_debug: print(f'Failed to generate assembly for \'{asm}\'')
            return asm, None

        full_patch = bytearray(b'\x90' * total_size)
        for i in range(0, len(asm_bytes)):
            full_patch[i] = asm_bytes[i]
        if print_debug: print(f'Patch: {asm} : {full_patch}')
        return asm, bytes(full_patch)
    except Exception as ex:
        print(f'Failed to generate patch: {ex}')
        return "N/A", bytes()

def apply_patch(ea, patch_bytes):
    print(f'apply_patch: {hex(ea)}: {patch_bytes}')
    ida_bytes.patch_bytes(ea, patch_bytes)

global Deobfuscator
try:
    Deobfuscator
    print(f'Deobfuscator already exists')
    if Deobfuscator is not None:
        Deobfuscator.Close(ida_kernwin.WCLS_SAVE)
        Deobfuscator = None
except:
    print('Deobfuscator doesn\'t exist')
    pass
    
Deobfuscator = DeobfuscatorPluginForm()
Deobfuscator.Show("Deobfuscator")

class DeobfuscatorHooks(ida_kernwin.UI_Hooks):
    deobfuscatorWizard : DeobfuscatorWizard = None
    last_function = None
    # def __init__(self, deobfuscatorWizard):
    #     self.deobfuscatorWizard = deobfuscatorWizard
    def screen_ea_changed(self, ea, prev_ea):
        try:
            if not self.deobfuscatorWizard.follow_checkbox.isChecked():
                return

            last_function = self.last_function
            current_function = db.functions.get_at(ea)
            self.last_function = current_function
            # print(f"{self.testValue}: screen_ea_changed: {hex(ea)}, {hex(prev_ea)}")
            # print(f'Switched func to: {current_function}')

            valid_range, start, end = idaapi.read_range_selection(None)
            destination = ea
            if valid_range:
                destination = start

            if self.deobfuscatorWizard.auto_deobfuscate_checkbox.isChecked() and last_function != None and last_function != current_function:
                obfuscations = find_obfuscations_in_function(destination)

                if len(obfuscations) > 0:
                    self.deobfuscatorWizard.ea = destination
                    self.deobfuscatorWizard.goto_next()
                    return

                # if len(obfuscations) > 0:
                    # print(f'Deobfuscations: {len(obfuscations)}')
                    # print(f'{obfuscations[0]}')
                    # for obfuscation in obfuscations:
                        # print(obfuscation[0])
                        # if obfuscation[0].startswith('r'):
                            # print(f'Skipping obfuscation {i}: {obfuscation[0]}')
                            # continue
                        # ob_ea = obfuscation[1][0].ea
                        # print(f'Obfuscation: {hex(ob_ea)}')
                        # self.deobfuscatorWizard.goto_address(ob_ea)
                        # self.deobfuscatorWizard.preview()
                        # return
                        # self.deobfuscatorWizard.patch()
                        # break

            self.deobfuscatorWizard.goto_address(destination)
            # self.deobfuscatorWizard.goto_next()
        except:
            pass

    def range(self):
        pass
        return

def find_obfuscations_in_function(ea):
    func = db.functions.get_at(ea)
    obfuscations = []
    for addr in func.code_items():
        obfuscation = check_for_obfuscation(addr)
        if obfuscation != False:
            obfuscations.append(obfuscation)
    return obfuscations

def check_for_obfuscation(ea):
    obfuscation_patterns = [
        [ida_allins.NN_mov, ida_allins.NN_add],
        [ida_allins.NN_mov, ida_allins.NN_sub],
        [ida_allins.NN_mov, ida_allins.NN_xor],
        # [ida_allins.NN_add, ida_allins.NN_add],
        # [ida_allins.NN_add, ida_allins.NN_sub],
        # [ida_allins.NN_sub, ida_allins.NN_add],
        # [ida_allins.NN_sub, ida_allins.NN_sub],
    ]

    instructions = []

    insn1 = db.instructions.get_at(ea)
    i1o1 = ida_domain.operands.OperandFactory.create(db, insn1.Op1, insn1)
    i1o2 = ida_domain.operands.OperandFactory.create(db, insn1.Op2, insn1)

    if (insn1 == None or i1o1 == None or i1o2 == None or i1o1.type != OperandType.REGISTER
            or (i1o2.type != OperandType.IMMEDIATE and i1o2.type != OperandType.MEMORY and
                i1o2.type != OperandType.FAR_ADDRESS and i1o2.type != OperandType.NEAR_ADDRESS)):
        return False

    # print(f'i1o1: {i1o1.type}')
    # print(f'i1o2: {i1o2.type}')

    instructions.append(insn1)

    register = i1o1.get_register_name()

    # if register.lower().startswith('r'):
        # print(f'ignoring check on register {register}')
        # return False

    # print(f'Continue with register {register}')
    previous_instruction = insn1
    # print(f'i1o2: {i1o2}: {i1o2.type}: {hex(i1o2.get_address())}')
    # print(f'{db.segments.get_at(i1o2.get_address()).perm}')

    if (i1o2.type == OperandType.MEMORY and i1o2.is_direct_memory() and i1o2.get_address()
            and (db.segments.get_at(i1o2.get_address()).perm != 7)):
            # and (db.segments.get_at(i1o2.get_address()).perm & ida_segment.SEGPERM_WRITE == 0)):
            # and i1o2.get_address() and ida_bytes.get_dword(i1o2.get_address()) < 0x10000):
        # print(f'Insn1 Arg 2 address')
        # print(f'Insn1 Arg 2 address: {hex(i1o2.get_address())} {db.segments.get_at(i1o2.get_address()).perm}')
        return False
    # if i1o2.type == OperandType.MEMORY and i1o2

    # print(f'Insn1: {hex(insn1.ea)}')

    while (previous_instruction != None):
        instruction = db.instructions.get_at(db.heads.get_next(previous_instruction.ea))
        op1 = ida_domain.operands.OperandFactory.create(db, instruction.Op1, instruction)
        op2 = ida_domain.operands.OperandFactory.create(db, instruction.Op2, instruction)

        if (instruction == None or op1 == None or op2 == None or op1.type != OperandType.REGISTER
                or op1.get_register_name() != register or op2.type == OperandType.REGISTER or
                op2.type == OperandType.DISPLACEMENT or instruction.itype == ida_allins.NN_cmp or
                instruction.itype == ida_allins.NN_shl or instruction.itype == ida_allins.NN_shr):
            # print(f'Ending obfuscation check at {hex(ea)}: {db.instructions.get_disassembly(db.instructions.get_at(instruction.ea))}')
            break

        # print(f'op2 address: {hex(op2.get_address())}')

        if (op2.type == OperandType.MEMORY and op2.is_direct_memory()
                and op2.get_address()
                # and op2.get_address() and (ida_bytes.get_dword(op2.get_address()) < 0xA00
                # or (db.segments.get_at(op2.get_address()).perm & ida_segment.SEGPERM_WRITE == 0))):
                # and (db.segments.get_at(op2.get_address()).perm & ida_segment.SEGPERM_WRITE == 0)):
                and (db.segments.get_at(op2.get_address()).perm != 7)):
            # print(f'Arg 2 address not in writeable memory: {hex(op2.get_address())} {db.segments.get_at(op2.get_address()).perm}')
                # and op2.get_address() and ida_bytes.get_dword(op2.get_address()) < 0x10000):
            return False

        # print(f'Instruction: {hex(instruction.ea)}')
        instructions.append(instruction)
        previous_instruction = instruction

    if len(instructions) < 2:
        return False

    matched_pattern = False

    # print(f'Obfuscation at: {hex(ea)}, {len(instructions)} instructions long. Pattern checking...')

    for pattern in obfuscation_patterns:
        pattern_found = True
        for i in range(0, len(pattern)):
            if i >= len(instructions):
                pattern_found = False
                break

            if instructions[i].itype != pattern[i]:
                pattern_found = False

        if pattern_found:
            # print(f'Pattern found: {pattern} at {hex(instructions[0].ea)}, register {register}')
            # print(f'Instructions: {len(instructions)}, Pattern: {len(pattern)}')
            # print(f'Pattern matched {i}: {instructions[i].itype} == {pattern[i]}')
            # print(f'{instructions[0].itype} : {instructions[1].itype}')
            matched_pattern = pattern
            break

    if not matched_pattern:
        return False

    # print(f'Obfuscation at: {hex(ea)}, {len(instructions)} instructions long')

    return register, instructions

# test1 = check_for_obfuscation(0x14CF38172)
# test2 = check_for_obfuscation(0x14CF38178)
# print(f'Test1: {"IsObfuscated" if test1 else "NotObfuscated"}')
# print(f'Test2: {"IsObfuscated" if test2 else "NotObfuscated"}')
# obfuscations = find_obfuscations_in_function(0x14E361333)

# for reg, instructions in find_obfuscations_in_function(0x14E361333):
#     # print(f'Obfuscation: {hex(instructions[0])}')
#     print(f'Obfuscation: {reg} {hex(instructions[0].ea)}')
#     for instruction in instructions:
#         asm = db.instructions.get_disassembly(db.instructions.get_at(instruction.ea))
#         op1 = ida_domain.operands.OperandFactory.create(db, instruction.Op1, instruction)
#         op2 = ida_domain.operands.OperandFactory.create(db, instruction.Op2, instruction)
#         print(f'\t{asm} {type(op1).__name__} {type(op2).__name__}')

global deobfuscatorHooks

try:
    if deobfuscatorHooks is not None:
        deobfuscatorHooks.unhook()
        deobfuscatorHooks = None
except:
    pass

deobfuscatorHooks = DeobfuscatorHooks()
Deobfuscator.deobfuscatorWizard.hooks = deobfuscatorHooks
deobfuscatorHooks.deobfuscatorWizard = Deobfuscator.deobfuscatorWizard
deobfuscatorHooks.hook()