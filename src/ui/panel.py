import customtkinter as ctk
from ui.binding import clear_placeholder, setup_console_bindings, setup_editor_bindings

def create_panel(app, parent, row, title,
                 subtitle, action, is_editor):

    panel = ctk.CTkFrame(
        parent,
        fg_color=app.theme["SURFACE"],
        corner_radius=12,
        border_width=1,
        border_color=app.theme["BORDER"]
    )
    panel.grid(
        row=row,
        column=0,
        sticky="nsew",
        pady=(0, 15) if row == 0 else 0
    )
    panel.grid_columnconfigure(0, weight=1)
    panel.grid_rowconfigure(1, weight=1)

    hdr = ctk.CTkFrame(panel, fg_color="transparent", height=65)
    hdr.grid(
        row=0,
        column=0,
        sticky="ew",
        padx=25,
        pady=(18, 12)
    )
    hdr.grid_propagate(False)

    title_box = ctk.CTkFrame(hdr, fg_color="transparent")
    title_box.pack(side="left")

    ctk.CTkLabel(
        title_box,
        text=title,
        font=("Segoe UI", 17, "bold"),
        text_color=app.theme["TEXT"]
    ).pack(anchor="w")

    if subtitle:
        ctk.CTkLabel(
            title_box,
            text=subtitle,
            font=("Segoe UI", 10),
            text_color=app.theme["TEXT_DIM"]
        ).pack(anchor="w", pady=(2, 0))

    ctk.CTkButton(
        hdr,
        text="Analyze Code" if action else "Clear",
        command=action or app.clear_console,
        width=140 if action else 100,
        height=40 if action else 36,
        font=("Segoe UI", 14, "bold") if action else ("Segoe UI", 13),
        fg_color=app.theme["ACCENT"]if action else app.theme["SURFACE_LIGHT"],
        hover_color=app.theme["ACCENT_HOVER"] if action else app.theme["BORDER"],
        corner_radius=8,
        border_width=0,
        text_color="white"if action else app.theme["TEXT_DIM"]
    ).pack(side="right")

    textbox = ctk.CTkTextbox(
        panel,
        fg_color=app.theme["SURFACE_LIGHT"],
        font=("Consolas", 15),
        text_color=app.theme["TEXT"],
        border_width=0,
        wrap="none" if is_editor else "word"
    )

    textbox.grid(
        row=1,
        column=0,
        sticky="nsew",
        padx=20,
        pady=(0, 20)
    )

    if is_editor:
        app.editor = textbox
        app.editor.configure(
            undo=True,
            maxundo=-1
        )
        setup_editor_bindings(app)
        app.editor.insert(
            "1.0",
            "// Paste your C code here\n"
            "// Supports: Ctrl+A, Ctrl+C, Ctrl+V, Ctrl+X, Ctrl+Z, Ctrl+Y"
        )
        app.editor.bind(
            "<FocusIn>",
            lambda e: clear_placeholder(app.editor),
            add="+"
        )

    else:
        app.console = textbox
        # app.console.configure(state="disabled")
        setup_console_bindings(app)