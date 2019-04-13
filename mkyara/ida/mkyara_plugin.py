from __future__ import print_function
import idaapi
import idc
from mkyara import (
    YaraGenerator,
)
from capstone import (
    CS_ARCH_X86,
    CS_MODE_16,
    CS_MODE_32,
    CS_MODE_64
)
from PyQt5 import QtGui, QtWidgets
from PyQt5.QtCore import Qt

INSTRUCTION_SET_MAPPING = {
    'metapc': CS_ARCH_X86,
}


def get_input_file_hash():
    return idc.GetInputMD5()


def get_selection():
    start = idc.SelStart()
    end = idc.SelEnd()
    if idaapi.BADADDR in (start, end):
        ea = idc.here()
        start = idaapi.get_item_head(ea)
        end = idaapi.get_item_end(ea)
    return start, end


def get_inf_structure_bitness(info):
    bits = 16
    if info.is_64bit():
        bits = 64
    elif info.is_32bit():
        bits = 32
    return bits


def get_arch_info():
    info = idaapi.get_inf_structure()
    proc = info.procName.lower()
    bits = get_inf_structure_bitness(info)
    instruction_set = None
    instruction_mode = None

    if proc == 'metapc':
        instruction_set = CS_ARCH_X86
        if bits == 16:
            instruction_mode = CS_MODE_16
        elif bits == 32:
            instruction_mode = CS_MODE_32
        elif bits == 64:
            instruction_mode = CS_MODE_64
    return instruction_set, instruction_mode


class YaraRuleDialog(QtWidgets.QDialog):
    def __init__(self, parent, clear_btn_clicked):
        super(YaraRuleDialog, self).__init__(parent)
        self.clear_btn_clicked = clear_btn_clicked
        self.populate_form()        

    def populate_form(self):
        self.setWindowTitle('mkYARA :: Generated Yara Rule')
        self.resize(800, 600)
        self.layout = QtWidgets.QVBoxLayout(self)
        self.top_layout = QtWidgets.QHBoxLayout()
        self.bottom_layout = QtWidgets.QHBoxLayout()
        self.bottom_layout.setAlignment(Qt.AlignRight | Qt.AlignBottom)
        # layout.addStretch()

        self.layout.addWidget(QtWidgets.QLabel("Generated Yara rule"))
        self.text_edit = QtWidgets.QTextEdit()
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setStyleHint(QtGui.QFont.Monospace)
        font.setFixedPitch(True)
        font.setPointSize(10)
        self.text_edit.setFont(font)
        metrics = QtGui.QFontMetrics(font)
        self.text_edit.setTabStopWidth(4 * metrics.width(' '))

        self.layout.addWidget(self.text_edit)

        self.clear_btn = QtWidgets.QPushButton("Clear")
        self.clear_btn.setFixedWidth(100)
        self.clear_btn.clicked.connect(self.clear_btn_clicked)
        self.clear_btn.clicked.connect(self.clear_btn_clicked_internal)
        self.bottom_layout.addWidget(self.clear_btn)

        self.ok_btn = QtWidgets.QPushButton("OK")
        self.ok_btn.setFixedWidth(100)
        self.ok_btn.clicked.connect(self.ok_btn_clicked)
        self.bottom_layout.addWidget(self.ok_btn)

        self.layout.addLayout(self.top_layout)
        self.layout.addLayout(self.bottom_layout)

    def ok_btn_clicked(self):
        self.close()

    def clear_btn_clicked_internal(self):
        self.text_edit.clear()


class mkYARAPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "mkYARA Plugin"
    help = "mkYARA Plugin"
    wanted_name = "mkYARA"
    wanted_hotkey = ""
    dialog = None
    yr_gen = None

    def init(self):
        loose_yara_action = idaapi.action_desc_t(
            'mkYARA:add_loose_yara',   # The action name. This acts like an ID and must be unique
            'Add Loose Yara Rule ',  # The action text.
            generic_handler(lambda: self.generate_yara_rule("loose")),   # The action handler.
            None,      # Optional: the action shortcut
            'Add loose yara rule',  # Optional: the action tooltip (available in menus/toolbar)
            199  # Optional: the action icon (shows when in menus/toolbars)
        )

        normal_yara_action = idaapi.action_desc_t(
            'mkYARA:add_normal_yara',   # The action name. This acts like an ID and must be unique
            'Add Normal Yara Rule ',  # The action text.
            generic_handler(lambda: self.generate_yara_rule("normal")),   # The action handler.
            'Ctrl+Y',      # Optional: the action shortcut
            'Add normal yara rule',  # Optional: the action tooltip (available in menus/toolbar)
            199  # Optional: the action icon (shows when in menus/toolbars)
        )

        strict_yara_action = idaapi.action_desc_t(
            'mkYARA:add_strict_yara',   # The action name. This acts like an ID and must be unique
            'Add Strict Yara Rule ',  # The action text.
            generic_handler(lambda: self.generate_yara_rule("strict")),   # The action handler.
            None,      # Optional: the action shortcut
            'Add strict yara rule',  # Optional: the action tooltip (available in menus/toolbar)
            199  # Optional: the action icon (shows when in menus/toolbars)
        )

        data_yara_action = idaapi.action_desc_t(
            'mkYARA:add_data_yara',   # The action name. This acts like an ID and must be unique
            'Add Data Yara Rule ',  # The action text.
            generic_handler(lambda: self.generate_yara_rule("normal", is_data=True)),   # The action handler.
            None,      # Optional: the action shortcut
            'Add data yara rule',  # Optional: the action tooltip (available in menus/toolbar)
            199  # Optional: the action icon (shows when in menus/toolbars)
        )

        string_yara_action = idaapi.action_desc_t(
            'mkYARA:add_string_yara',   # The action name. This acts like an ID and must be unique
            'Add String Yara Rule ',  # The action text.
            generic_handler(lambda: self.generate_yara_rule("string")),   # The action handler.
            'Ctrl+N',      # Optional: the action shortcut
            'Add string yara rule',  # Optional: the action tooltip (available in menus/toolbar)
            199  # Optional: the action icon (shows when in menus/toolbars)
        )

        generate_yara_action = idaapi.action_desc_t(
            'mkYARA:generate_yara_rule',   # The action name. This acts like an ID and must be unique
            'Generate Yara Rule ',  # The action text.
            generic_handler(lambda: self.generate_yara_rule("generate")),   # The action handler.
            'Ctrl+Shift+Y',      # Optional: the action shortcut
            'Generate yara rule',  # Optional: the action tooltip (available in menus/toolbar)
            199  # Optional: the action icon (shows when in menus/toolbars)
        )

        idaapi.register_action(loose_yara_action)
        idaapi.register_action(normal_yara_action)
        idaapi.register_action(strict_yara_action)
        idaapi.register_action(data_yara_action)
        idaapi.register_action(string_yara_action)
        idaapi.register_action(generate_yara_action)
        self.ui_hooks = mkYARAUIHooks()
        self.ui_hooks.hook()
        print('mkYARA :: Plugin Started')
        return idaapi.PLUGIN_KEEP

    def clear_yara(self):
        self.yr_gen = None

    def generate_yara_rule(self, mode, is_data=False):        
        if self.yr_gen == None:
            ins_set, ins_mode = get_arch_info()
            self.yr_gen = YaraGenerator(ins_set, ins_mode)
        
        if mode == 'generate':
            if self.dialog == None:
                self.dialog = YaraRuleDialog(None, self.clear_yara)
            self.dialog.show()
        else:
            start, end = get_selection()
            size = end - start
            data = idaapi.get_many_bytes(start, size)
            self.yr_gen.add_chunk(data, mode, offset=start, is_data=is_data)
            print("Added pattern of type {}: {}  ".format(mode, repr(data)))

        if self.dialog != None:
            rule_obj = self.yr_gen.generate_rule()
            file_hash = get_input_file_hash()
            rule_obj.metas["hash"] = "\"{}\"".format(file_hash)
            rule = rule_obj.get_rule_string()
            self.dialog.text_edit.clear()
            self.dialog.text_edit.insertPlainText(rule)    


    def term(self):
        self.ui_hooks.unhook()

    def run(self, arg):
        pass


def generic_handler(callback):
    class Handler(idaapi.action_handler_t):
            def __init__(self):
                idaapi.action_handler_t.__init__(self)

            def activate(self, ctx):
                callback()
                return 1

            def update(self, ctx):
                return idaapi.AST_ENABLE_ALWAYS
    return Handler()


class mkYARAUIHooks(idaapi.UI_Hooks):
    def populating_tform_popup(self, form, popup):
        pass

    def finish_populating_tform_popup(self, form, popup):
        idaapi.attach_action_to_popup(form, popup, "mkYARA:add_loose_yara", "mkYARA/")
        idaapi.attach_action_to_popup(form, popup, "mkYARA:add_normal_yara", "mkYARA/")
        idaapi.attach_action_to_popup(form, popup, "mkYARA:add_strict_yara", "mkYARA/")
        idaapi.attach_action_to_popup(form, popup, "mkYARA:add_data_yara", "mkYARA/")
        idaapi.attach_action_to_popup(form, popup, "mkYARA:add_string_yara", "mkYARA/")
        idaapi.attach_action_to_popup(form, popup, "mkYARA:generate_yara_rule", "mkYARA/")
        


plugin = mkYARAPlugin()
def PLUGIN_ENTRY():
    global plugin
    return plugin
