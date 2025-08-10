# For Oblivion Remaster
# Checks all the code refs to a list of common functions that generate and run a VHandler, specifying which argument to each function
# is associated with the name of the command and which argument is the function to be called. Renames unnamed functions to match the name
# of the command that accompanies them.

global updated_count
global newly_updated_count
try:
    updated_count = updated_count
except Exception as ex:
    updated_count = 0


def GetFuncArg(ea, arg):
    cfunc = ida_hexrays.decompile(ea)
    item = cfunc.body.find_closest_addr(ea)
    return item.to_specific_type.a[arg]


def UpdateHandler(ea, textArg, funcArg):
    global updated_count
    global newly_updated_count
    newly_updated_count = 0
    cfunc = ida_hexrays.decompile(ea)
    if cfunc == None:
        print(f'Failed to get func body for ea {hex(ea)}')
        return
    item = cfunc.body.find_closest_addr(ea).to_specific_type
    handler_name = None
    func = None

    try:
        handler_name = item.a[textArg].dstr().lstrip('"').rstrip('"').replace(' ', '_')
        # ida_name.get_name_ea(0, "FadeFromMoveToInExterior")
        if len(handler_name) < 6:
            print(f'Failed to get handler_name for ea {hex(ea)}. Arg {textArg} is not a string: {handler_name}')
            return
        # if item.a[textArg].x == None:
        # print(f'Failed to get handler_name for ea {hex(ea)}. Arg {textArg} is not a string: {handler_name}')
        # return
    except Exception as ex:
        print(f'Failed to get handler_name for ea {hex(ea)}')
        return

    try:
        if item.a[funcArg].x == None:
            if item.a[funcArg].obj_ea == None:
                if len(item.a[funcArg].dstr()) > 6:
                    func = item.a[funcArg].dstr()
                else:
                    print(f'Failed to get func for ea {hex(ea)}. Arg {funcArg} is not a string: {func}')
                    return
            else:
                func = item.a[funcArg].obj_ea
        else:
            func = item.a[funcArg].x.obj_ea
    except Exception as ex:
        print(f'Failed to get func address for ea {hex(ea)}')
        return

    if handler_name != None and func != None:
        func_name = idaapi.get_name(func)
        if func_name.startswith("sub_"):
            print(f'Updating handler at {hex(ea)}: {handler_name}. Function: {func_name}({hex(func)})')
            # result = ida_name.set_name(func, handler_name)
            result = idaapi.set_name(func, handler_name, idaapi.SN_NOCHECK | idaapi.SN_FORCE | idaapi.SN_NOWARN)
            print(f'Rename attempt: {result}')
            updated_count = updated_count + 1
            newly_updated_count = newly_updated_count + 1
        else:
            # print(f'Skipping handler at {hex(ea)}: {handler_name}. Function: {func_name}({hex(func)})')
            pass


def UpdateHandler9s(ea):
    UpdateHandler(ea, 3, 4)


def UpdateCommandRefs(ea, textArg, funcArg):
    for xref in CodeRefsTo(ea, True):
        UpdateHandler(xref, textArg, funcArg)


UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_0"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_1"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_10"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_11"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_12"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_13"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_14"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_15"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_16"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_17"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_18"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_19"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_2"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_20"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_21"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_22"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_24"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_25"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_26"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_27"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_28"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_29"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_3"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_30"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_32"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_33"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_34"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_35"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_4"), 3, 4)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_5"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_6"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_7"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_8"), 1, 2)
UpdateCommandRefs(ida_name.get_name_ea(0, "CreateAndFireCommand_9"), 1, 2)

print(f'Updated count: {updated_count}, Newly Updated: {newly_updated_count}')