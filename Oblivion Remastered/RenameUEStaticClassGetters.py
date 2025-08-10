# For Oblivion Remaster
# Iterates all code refs to a UE function that creates a Static Default Object for a UE class, automatically renaming the function that
# is used to get or create this SDO, renaming potentially thousands of functions.
from PyQt5.QtWidgets import QApplication
import qasync
import asyncio
import time

global updated_getstaticclass_count
try:
    updated_getstaticclass_count
except:
    updated_getstaticclass_count = 0

qapp = QApplication.instance()
loop = qasync.QEventLoop(qapp, already_running=True)
asyncio.set_event_loop(loop)


def update_GetStaticClass_ref(xref, i):
    global updated_getstaticclass_count
    # print(f'Running on xref: {xref}')
    # start_time = time.time()
    cfunc = ida_hexrays.decompile(xref)
    # print(f'--- decompile:          {time.time() - start_time}')
    # start_time = time.time()
    item = cfunc.body.find_closest_addr(xref).to_specific_type
    # print(f'--- find_closest_addr:  {time.time() - start_time}')
    current_name = ida_name.get_name(cfunc.entry_ea)
    if not current_name.startswith("sub_"):
        print(f'{i}.) {hex(xref)} {current_name} is already named.')
        return
    class_name = item.a[1].dstr()
    if not class_name.startswith('L"'):
        print(f'{i}.) {hex(xref)} {current_name} invalid class_name: {class_name}.')
        return
    class_name = class_name.lstrip('L').replace('"', '')
    first_line = cfunc.body.find_closest_addr(cfunc.entry_ea).to_specific_type
    if not first_line.dstr().startswith('result = '):
        print(f'{i}.) {hex(xref)} {current_name} first line isn\'t "result =...": {first_line.dstr()}.')
        return
    first_line_loc_name = ida_name.get_name(first_line.y.obj_ea)
    if not first_line_loc_name.startswith('qword'):
        print(f'{i}.) {hex(xref)} {current_name} first line loc name isn\'t "qword_...": {first_line_loc_name}.')
        return
    print(f'{i}.) {hex(xref)} {current_name} needs updated. Valid class_name:     {class_name}')
    new_func_name = f'GetStaticClass_{class_name}'
    # start_time = time.time()
    result = idaapi.set_name(cfunc.entry_ea, new_func_name, idaapi.SN_NOCHECK | idaapi.SN_FORCE | idaapi.SN_NOWARN)
    # print(f'--- set_name func  :{time.time() - start_time}')
    if not result:
        print(f'        Failed to rename function {current_name} to {new_func_name}')
    new_global_name = f'Static_{class_name}'
    # start_time = time.time()
    result = idaapi.set_name(first_line.y.obj_ea, new_global_name, idaapi.SN_NOCHECK | idaapi.SN_FORCE | idaapi.SN_NOWARN)
    # print(f'--- set_name global:{time.time() - start_time}')
    if not result:
        print(f'        Failed to rename global {first_line_loc_name} to {new_global_name}')
    updated_getstaticclass_count = updated_getstaticclass_count + 1


async def update_GetStaticClass_refs():
    ea = 0x140FFF290
    limit = 6000
    start = 0
    end = start + limit
    i = 0

    for xref in CodeRefsTo(ea, True):
        i = i + 1
        if i < start:
            continue
        if i >= end:
            break
        # await asyncio.to_thread(update_GetStaticClass_ref, xref)

        # start_time = time.time()
        update_GetStaticClass_ref(xref, i)
        # await asyncio.to_thread(update_GetStaticClass_ref, xref)
        # print(f'--- Total time:{time.time() - start_time}')
        # await update_GetStaticClass_ref(xref)

    print(f'Updated count: {updated_getstaticclass_count}')

    # else:
    #    print(f'{i}.) {hex(xref)} {current_name} needs updated. Invalid class_name: {class_name}')


# cfunc = ida_hexrays.decompile(ea)

# asyncio.ensure_future(update_GetStaticClass_refs())
asyncio.create_task(update_GetStaticClass_refs())