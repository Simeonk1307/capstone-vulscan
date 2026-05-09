import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import os
import tempfile
from pathlib import Path
from core.scanner import ScanEngine
from core.report_gen import create_report
from ui.theme import LIGHT, DARK
from ui.logger import ConsoleLogger
from ui.header import create_header
from ui.panel import create_panel
import sys

if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys._MEIPASS)
else:
    BASE_DIR = Path(__file__).parent.resolve()

class VulScan(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("VulScan-LT++ - Security Vulnerability Scanner")
        self.geometry("1400x900")
        self.minsize(1000, 700)

        self.is_dark_mode = True
        self.theme = DARK.copy()
        self.configure(fg_color=self.theme["BG"])

        self.scanner_engine = None
        self.scan_results = {}
        self.is_scanning = False
        self.files_scanned = 0
        self.cancel_requested = False

        self.build_ui()
        self.logger = ConsoleLogger(self.console, self.theme)
        
        threading.Thread(target=self.load_engine, daemon=True).start()

    def load_engine(self):
        try:
            model_path     = BASE_DIR / "models" / "model.onnx"
            tokenizer_path = BASE_DIR / "models" / "tokenizer_fast"
            classes_path   = BASE_DIR / "models" / "classes.npy"

            self.scanner_engine = ScanEngine(str(model_path), str(tokenizer_path), str(classes_path))
            self.after(0, lambda: self.logger.log("[SYSTEM] Scanner engine ready\n", self.theme["SUCCESS"]))
        except Exception as e:
            self.after(0, lambda err=str(e): self._handle_engine_error(err))

    def _handle_engine_error(self, msg):
        messagebox.showerror("Error", msg)
        self.destroy()

    def toggle_theme(self):
        editor_content  = self.editor.get("1.0", "end-1c")
        console_content = self.console.get("1.0", "end-1c")

        self.is_dark_mode = not self.is_dark_mode
        self.theme = DARK.copy() if self.is_dark_mode else LIGHT.copy()

        ctk.set_appearance_mode("dark" if self.is_dark_mode else "light")

        for widget in self.winfo_children():
            widget.destroy()

        self.configure(fg_color=self.theme["BG"])
        self.build_ui()
        self.logger = ConsoleLogger(self.console, self.theme)

        self.editor.delete("1.0", "end")
        self.editor.insert("1.0", editor_content)

        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.insert("1.0", console_content)
        self.console.configure(state="disabled")

    def build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        create_header(self)

        ws = ctk.CTkFrame(self, fg_color="transparent")
        ws.grid(row=1, column=0, sticky="nsew", padx=25, pady=20)
        ws.grid_columnconfigure(0, weight=1)
        ws.grid_rowconfigure(0, weight=3)
        ws.grid_rowconfigure(1, weight=2)

        create_panel(self, ws, 0, "Code Editor", "Paste C/C++ code to analyze", self.analyze, True)
        create_panel(self, ws, 1, "Scan Results", None, None, False)

        prog = ctk.CTkFrame(self, fg_color=self.theme["SURFACE"], height=10, corner_radius=0)
        prog.grid(row=2, column=0, sticky="ew")
        prog.grid_propagate(False)

        self.progress = ctk.CTkProgressBar(
            prog,
            height=10,
            progress_color=self.theme["ACCENT"],
            fg_color=self.theme["BORDER"],
            corner_radius=0
        )
        self.progress.pack(fill="x")
        self.progress.set(0)

    def clear_console(self):
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")

    def scan(self, mode):
        if self.is_scanning or not self.scanner_engine:
            return

        path = filedialog.askdirectory(title="Select Directory") if mode == "dir" else \
               filedialog.askopenfilename(title="Select File", filetypes=[("C/C++ Files", "*.c *.h")])

        if not path: return
        self.start_scan(path, mode)

    def start_scan(self, path, mode):
        self.is_scanning = True
        self.cancel_requested = False
        self.files_scanned = 0
        self.scan_results = {}

        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")

        if mode == "dir":
            self.logger.log(f"[SYSTEM] Scanning directory: {path}\n\n", self.theme["ACCENT"])
        elif mode == "file":
            self.logger.log(f"[SYSTEM] Scanning file: {os.path.basename(path)}\n\n", self.theme["ACCENT"])
        else:
            self.logger.log("[SYSTEM] Analyzing editor code...\n\n", self.theme["WARNING"])

        self.progress.set(0)
        self.btn_export.configure(state="disabled")
        self.btn_cancel.configure(state="normal")

        if mode != "editor":
            self.btn_dir.configure(state="disabled")
            self.btn_file.configure(state="disabled")

        threading.Thread(target=self.worker, args=(path, mode), daemon=True).start()

    def cancel_scan(self):
        if self.is_scanning:
            self.cancel_requested = True
            self.logger.log("\n[SYSTEM] Cancellation requested...\n", self.theme["WARNING"])

    def analyze(self):
        if self.is_scanning:
            return

        code = self.editor.get("1.0", "end-1c")

        if not code.strip() or code.lstrip().startswith("//"):
            messagebox.showinfo("Empty", "Enter code first")
            return

        with tempfile.NamedTemporaryFile(suffix=".c", mode='w', delete=False, encoding='utf-8') as f:
            f.write(code)
            temp_path = f.name

        self.start_scan(temp_path, "editor")

    def worker(self, path, mode):
        try:
            cancel = lambda: self.cancel_requested

            if mode == "dir":
                self.after(0, lambda: self.logger.log("[SYSTEM] Walking directory tree...\n", self.theme["TEXT_DIM"]))

                def on_file(name, current, total):
                    self.after(0, lambda n=name: self.logger.log(f"[SCAN] Reading: {n}\n", self.theme["TEXT_DIM"]))
                    self.after(0, lambda: self.progress.set(current / total))

                self.scan_results  = self.scanner_engine.scan_dir(path, on_file=on_file, cancel_flag=cancel)
                self.files_scanned = len(self.scan_results)

            else:
                self.after(0, lambda: self.logger.log("[SCAN] Processing file...\n", self.theme["TEXT_DIM"]))
                _, vuls            = self.scanner_engine.scan_file(path, cancel_flag=cancel)
                self.scan_results  = {path: vuls}
                self.files_scanned = 1

            if self.cancel_requested:
                self.after(0, self.handle_cancel)
                return

            self.after(0, lambda: self.logger.log("[SYSTEM] Scan completed.\n", self.theme["SUCCESS"]))
            self.after(0, lambda: self.show_results(mode))

        except Exception as e:
            self.after(0, lambda err=str(e): self.logger.log(f"\n[ERROR] {err}\n", self.theme["ERROR"]))
            self.after(0, lambda: self.progress.set(0))
        finally:
            self.is_scanning = False
            self.after(0, lambda: (
                self.btn_dir.configure(state="normal"),
                self.btn_file.configure(state="normal"),
                self.btn_cancel.configure(state="disabled")
            ))

    def handle_cancel(self):
        self.scan_results  = {}
        self.files_scanned = 0
        self.logger.log("\n[SYSTEM] Scan cancelled by user.\n", self.theme["WARNING"])
        self.progress.set(0)
        self.btn_export.configure(state="disabled")

    def show_results(self, mode):
        total            = sum(len(v) for v in self.scan_results.values())
        files_with_issues = sum(1 for v in self.scan_results.values() if v)

        self.logger.log("=" * 90 + "\n", self.theme["BORDER"])
        if mode == "dir":
            self.logger.log(f"Scanned {self.files_scanned} files\n", self.theme["TEXT"])

        if total == 0:
            self.logger.log("No vulnerabilities found\n", self.theme["SUCCESS"])
        else:
            color = self.theme["ERROR"] if total > 10 else self.theme["WARNING"]
            self.logger.log(f"Found {total} issue(s) in {files_with_issues} file(s)\n", color)

        self.logger.log("=" * 90 + "\n\n", self.theme["BORDER"])

        for path, issues in self.scan_results.items():
            if not issues:
                continue

            name = "EDITOR" if mode == "editor" else os.path.basename(path)
            self.logger.log(f"File: {name}\n", self.theme["ACCENT"])
            self.logger.log("-" * 90 + "\n", self.theme["BORDER"])

            for idx, issue in enumerate(issues, 1):
                critical = "CRITICAL" in issue.get('cwe', '').upper()
                color    = self.theme["ERROR"] if critical else self.theme["WARNING"]

                self.logger.log(f"\n  Issue #{idx}\n",                                    self.theme["TEXT"])
                self.logger.log(f"  Severity: {'CRITICAL' if critical else 'WARNING'}\n", color)
                self.logger.log(f"  Line: {issue['line']}\n",                             self.theme["TEXT"])
                self.logger.log(f"  Type: {issue['cwe']}\n",                              self.theme["TEXT"])
                self.logger.log(f"  Code: {issue['code'][:75]}...\n",                     self.theme["TEXT_DIM"])

        self.progress.set(1.0)
        self.btn_export.configure(state="normal")
        self.logger.log("\nUse 'Export Report' to generate PDF\n", self.theme["TEXT_DIM"])

    def export(self):
        dest = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
        if not dest:
            return

        try:
            data = {f"{os.path.basename(f)}:L{i['line']}": i
                    for f, issues in self.scan_results.items() for i in issues}
            create_report(data, "VulScan Security Report", dest)
            messagebox.showinfo("Success", f"Report saved to:\n{dest}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    app = VulScan()
    app.mainloop()