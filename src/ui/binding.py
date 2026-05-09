def select_all(widget):
    widget.tag_remove("sel", "1.0", "end")
    widget.tag_add("sel", "1.0", "end-1c")
    return "break"


def copy_text(widget, root):
    try:
        selected = widget.get("sel.first", "sel.last")
        root.clipboard_clear()
        root.clipboard_append(selected)
    except:
        pass
    return "break"


def cut_text(widget, root):
    try:
        selected = widget.get("sel.first", "sel.last")

        root.clipboard_clear()
        root.clipboard_append(selected)

        widget.delete("sel.first", "sel.last")

    except:
        pass

    return "break"


def paste_text(widget, root):
    try:
        text = root.clipboard_get()

        try:
            widget.delete("sel.first", "sel.last")
        except:
            pass

        widget.insert("insert", text)

    except:
        pass

    return "break"


def clear_placeholder(editor):
    content = editor.get("1.0", "end-1c")

    if content.startswith("//"):
        editor.delete("1.0", "end")

    editor.unbind("<FocusIn>")


def setup_editor_bindings(app):
    binds = {
        "<Control-a>": lambda e: select_all(app.editor),
        "<Control-A>": lambda e: select_all(app.editor),
        "<Control-c>": lambda e: copy_text(app.editor, app),
        "<Control-C>": lambda e: copy_text(app.editor, app),
        "<Control-x>": lambda e: cut_text(app.editor, app),
        "<Control-X>": lambda e: cut_text(app.editor, app),
        "<Control-v>": lambda e: paste_text(app.editor, app),
        "<Control-V>": lambda e: paste_text(app.editor, app),
    }
    for key, func in binds.items():
        app.editor.bind(key, func)


def setup_console_bindings(app):
    binds = {
        "<Control-a>": lambda e: select_all(app.console),
        "<Control-A>": lambda e: select_all(app.console),
        "<Control-c>": lambda e: copy_text(app.console, app),
        "<Control-C>": lambda e: copy_text(app.console, app),
    }
    for key, func in binds.items():
        app.console.bind(key, func)