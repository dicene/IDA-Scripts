# IDA Scripts
Various scripts I use with IDA when reverse-engineering an application. Requires IDAPython, and written for IDA 9.0 (although they might mostly be compatible with older versions.

## General
### [CustomDisplayHook.py](https://github.com/dicene/IDA-Scripts/blob/main/CustomDisplayHook.py)
Replaces the default displayhook with a new version that displays numbers in hex AND decimal.
### [UpdateSelectedStrings.py](https://github.com/dicene/IDA-Scripts/blob/main/UpdateSelectedStrings.py)
Registers a Hotkey to Shift+A that attempts to automatically rename all strings in your current selection based on their text content, and attempts to automatically translate Japanese text to English string names via GoogleTranslator.
### [idapythonrc.py](https://github.com/dicene/IDA-Scripts/blob/main/idapythonrc.py)
A script that IDA automatically runs upon opening (if placed in the appropriate folder). Adds a bunch of convenience functions and defaults the console to Python.
### [FFT_Deobfuscator.py](https://github.com/dicene/IDA-Scripts/blob/main/FFT_Deobfuscator.py)
This script opens a wizard for repairing some of the Denuvo constant obfuscations present in FFT. Might work in other games, but there is some hard-coding in it to only detect obfuscations in certain regions of memory, which might need to be altered or removed to use with other projects.
The code is REALLY unclean and isn't really suitable for wide-release, but it's functional and makes working in the current Denuvo-enabled version of FFT a little easier.
tl;dr instructions: Run script from "Script File" or "Script Command" to open the plugin window. Clicking anywhere in Pseudocode or Disassembly will cause the plugin to follow to your cursor location. If your cursor is on the first line of an obfuscation, it'll be displayed in the plugin form (so clicking around in Pseudocode might not work as reliably as clicking on the obfuscation in the disassembly). You can hit Next to attempt to find an obfuscation in the current function that your cursor is in. Patch will patch the displayed obfuscation. Patch All will patch all deobfuscations in the current function.

## Oblivion Remaster specific
### [RenameFunctionsFromCommandNames.py](https://github.com/dicene/IDA-Scripts/blob/main/Oblivion%20Remastered/RenameFunctionsFromCommandNames.py)
Checks all the code refs to a list of common functions that generate and run a VHandler, specifying which argument to each function is associated with the name of the command and which argument is the function to be called. Renames unnamed functions to match the name of the command that accompanies them.
### [RenameUEStaticClassGetters.py](https://github.com/dicene/IDA-Scripts/blob/main/Oblivion%20Remastered/RenameUEStaticClassGetters.py)
Iterates all code refs to a UE function that creates a Static Default Object for a UE class, automatically renaming the function that is used to get or create this SDO, renaming potentially thousands of functions.
