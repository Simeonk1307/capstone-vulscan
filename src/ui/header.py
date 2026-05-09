import customtkinter as ctk

def create_header(app):
    header = ctk.CTkFrame(
        app,
        fg_color=app.theme["SURFACE"],
        height=80,
        corner_radius=0
    )
    header.grid(row=0, column=0, sticky="ew")
    header.grid_propagate(False)

    title = ctk.CTkFrame(header, fg_color="transparent")
    title.pack(side="left", padx=30, pady=20)

    ctk.CTkLabel(
        title,
        text="VulScan",
        font=("Segoe UI", 26, "bold"),
        text_color=app.theme["ACCENT"]
    ).pack(anchor="w")

    ctk.CTkLabel(
        title,
        text="Security Vulnerability Scanner",
        font=("Segoe UI", 11),
        text_color=app.theme["TEXT_DIM"]
    ).pack(anchor="w")

    btns = ctk.CTkFrame(header, fg_color="transparent")
    btns.pack(side="right", padx=30, pady=20)

    app.btn_dir = ctk.CTkButton(
        btns,
        text="Scan Directory",
        command=lambda: app.scan("dir"),
        fg_color=app.theme["ACCENT"],
        hover_color=app.theme["ACCENT_HOVER"],
        text_color=app.theme["TEXT"],
    )
    app.btn_dir.pack(side="left", padx=6)

    app.btn_file = ctk.CTkButton(
        btns,
        text="Scan File",
        command=lambda: app.scan("file"),
        fg_color=app.theme["ACCENT"],
        hover_color=app.theme["ACCENT_HOVER"],
        text_color=app.theme["TEXT"],
    )
    app.btn_file.pack(side="left", padx=6)

    app.btn_export = ctk.CTkButton(
        btns,
        text="Export Report",
        command=app.export,
        fg_color=app.theme["BORDER"],
        hover_color=app.theme["SURFACE_LIGHT"],
        text_color=app.theme["TEXT"],
    )
    app.btn_export.pack(side="left", padx=6)

    app.btn_cancel = ctk.CTkButton(
        btns,
        text="Cancel",
        command=app.cancel_scan,
        state="disabled",
        fg_color=app.theme["WARNING"],
        hover_color=app.theme["ERROR"],
        text_color=app.theme["TEXT"],
    )
    app.btn_cancel.pack(side="left", padx=6)

    theme_icon = "☀️" if app.is_dark_mode else "🌙"

    ctk.CTkButton(
        btns,
        text=theme_icon,
        command=app.toggle_theme,
        width=42,
        height=42,
        font=("Segoe UI", 16),
        fg_color=app.theme["SURFACE_LIGHT"],
        hover_color=app.theme["BORDER"],
        text_color=app.theme["TEXT"],
        corner_radius=8,
        border_width=0
    ).pack(side="left", padx=6)