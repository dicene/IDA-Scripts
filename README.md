# IDA Scripts
Various scripts I use with IDA when reverse-engineering an application. Requires IDAPython, and written for IDA 9.0 (although they might mostly be compatible with older versions.

## General
### [CustomDisplayHook.py](https://github.com/dicene/IDA-Scripts/blob/main/CustomDisplayHook.py)
Replaces the default displayhook with a new version that displays numbers in hex AND decimal.
### [UpdateSelectedStrings.py](https://github.com/dicene/IDA-Scripts/blob/main/UpdateSelectedStrings.py)
Registers a Hotkey to Shift+A that attempts to automatically rename all strings in your current selection based on their text content, and attempts to automatically translate Japanese text to English string names via GoogleTranslator.
### [idapythonrc.py](https://github.com/dicene/IDA-Scripts/blob/main/idapythonrc.py)
My version of the script that IDA automatically runs upon opening. Adds a bunch of convenience functions defaults the console to Python.

## Oblivion Remaster specific
### [RenameFunctionsFromCommandNames.py](https://github.com/dicene/IDA-Scripts/blob/main/Oblivion%20Remastered/RenameFunctionsFromCommandNames.py)
Checks all the code refs to a list of common functions that generate and run a VHandler, specifying which argument to each function is associated with the name of the command and which argument is the function to be called. Renames unnamed functions to match the name of the command that accompanies them.
### [RenameUEStaticClassGetters.py](https://github.com/dicene/IDA-Scripts/blob/main/Oblivion%20Remastered/RenameUEStaticClassGetters.py)
Iterates all code refs to a UE function that creates a Static Default Object for a UE class, automatically renaming the function that is used to get or create this SDO, renaming potentially thousands of functions.
