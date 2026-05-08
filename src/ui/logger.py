class ConsoleLogger:
    def __init__(self, console, theme):
        self.console = console
        self.theme = theme

    def log(self, msg, color=None):
        if color is None:
            color = self.theme["TEXT"]

        self.console.configure(state="normal")
        self.console.insert("end", msg)

        start = self.console.index("end-2c linestart")
        end = self.console.index("end-1c")

        tag = f"t{id(msg)}"

        self.console.tag_add(tag, start, end)
        self.console.tag_config(tag, foreground=color)

        self.console.see("end")
        self.console.configure(state="disabled")