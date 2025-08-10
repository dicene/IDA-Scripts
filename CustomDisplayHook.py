# Replaces the default displayhook with a new version that displays numbers in hex AND decimal
# Automatically calls dir() on custom classes to display all their property names to make examining IDA python results faster and easier

try:
    original_displayhook
except Exception as ex:
    print("No original displayhook. Backing the original up before overriding...")
    original_displayhook = sys.displayhook

def new_displayhook(thing):
    if thing == None:
        print('None')
    elif type(thing) == int:
        print(f'{hex(thing)}: {thing}')
    elif type(thing) == bool:
        print(thing)
    elif type(thing) == str:
        print(f'"{thing}"')
    elif type(thing).__module__ == "__builtin__":
        print(f'Built-in: {type(thing)}\n{thing}')
    else:
        print(f'{dir(thing)}\n{thing}\n')

sys.displayhook = new_displayhook

sys.displayhook(a)