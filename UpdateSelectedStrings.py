# Registers a Hotkey to Shift+A that attempts to automatically rename all strings in your current selection based on their text content
# Also attempts to automatically translate any Japanese strings to English names via GoogleTranslator

from PyQt5.QtWidgets import QApplication
import qasync
import asyncio
import idaapi
import ida_bytes
import re
from deep_translator import GoogleTranslator

qapp = QApplication.instance()
loop = qasync.QEventLoop(qapp, already_running=True)
asyncio.set_event_loop(loop)


def has_japanese_characters(text):
    japanese_pattern = re.compile(r'[\u3040-\u30ff\u4e00-\u9fff]')
    return japanese_pattern.search(text) is not None


def is_instruction(ea):
    return idaapi.is_code(idaapi.get_flags(ea))


def is_offset(ea):
    return ida_bytes.is_off0(ida_bytes.get_flags(ea))


try:
    ida_kernwin.del_hotkey(update_strings_hotkey)
    print('Deleted existing update_selected_string hotkey.')
except NameError:
    pass


async def update_string(ea_to_update, print_results=False):
    if print_results: print(f'Attempting to update string at {hex(ea_to_update)}')

    # if ida_bytes.get_full_flags(ea_to_update) & 0x80 == 0x80:
    str_type = idc.get_str_type(ea_to_update)
    if str_type is None:
        if is_offset(ea_to_update):
            target_address = ida_bytes.get_qword(ea_to_update)
            print(f'EA is an offset to: {hex(target_address)}')
            target_str_type = idc.get_str_type(target_address)
            if target_str_type is None:
                return

            print(f'Address pointed to by {hex(ea_to_update)} is a string!')

            await update_string(target_address, print_results=False)
            if ida_bytes.has_name(target_address):
                target_name = ida_name.get_name(target_address)
                print(f'Target has name: {target_name}')
                ida_name.make_name_auto(ea_to_update)
                ida_name.set_name(ea_to_update, f'a{target_name}')

        return

    print(f'Str_type: {hex(str_type)}')
    if str_type == idc.STRTYPE_C_16:
        # is unicode
        text = ida_bytes.get_strlit_contents(ea_to_update, -1, ida_nalt.STRTYPE_C_16).decode()

        if has_japanese_characters(text):
            print(f'Translating Unicode: {text}')
            translator = GoogleTranslator(source='ja', target='en')
            result = await asyncio.to_thread(translator.translate, text)
            # result = translator.translate(text)
            print(f'Translated: {result}')
            text = result.title().replace(' ', '')

        if print_results: print(f'Text UNICODE: ({len(text)}) {text}')

        text = f'a{text}'
    else:
        text = ida_bytes.get_strlit_contents(ea_to_update, -1, ida_nalt.STRTYPE_C).decode('utf-8')

        if has_japanese_characters(text):
            print(f'Translating: {text}')
            translator = GoogleTranslator(source='ja', target='en')
            result = await asyncio.to_thread(translator.translate, text)
            # result = translator.translate(text)
            # print(f'Translated: {result}')
            text = result.title().replace(' ', '')
        else:
            text = text.replace(' ', '')

        if print_results: print(f'Text C: ({len(text)}) {text}')

        text = f'a{text}'
    # print(f'Attempting to rename {get_name(ea_to_update)} to {text}...')
    if idaapi.set_name(ea_to_update, text, idaapi.SN_NOCHECK | idaapi.SN_FORCE):
        new_name = get_name(ea_to_update)
        # print(f'Renamed to {new_name}!')
    else:
        print(f'Failed to rename {hex(ea_to_update)} to: {text}')


async def update_strings():
    print_results = False
    t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
    if idaapi.read_selection(view, t0, t1):
        start, end = t0.place(view).toea(), t1.place(view).toea()
        # print(f'start:{hex(start)}, end:{hex(end)}, size:{hex(size)}')
        for ea in Heads(start, end + 1):
            if not is_instruction(ea):
                print(f'Updating: {hex(ea)}')
                await update_string(ea, print_results)
    #        insn = idaapi.insn_t()
    # print(f'{hex(ea)}: {insn}')
    else:
        await update_string(get_screen_ea(), print_results)

    print('\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n')
    print('======--======--======--======--==================--======--======--======--======--======')
    print('FINISHED UPDATING STRINGS!')
    print('======--======--======--======--==================--======--======--======--======--======')


update_strings_hotkey = idaapi.add_hotkey("Shift+A", lambda: asyncio.ensure_future(update_strings()))