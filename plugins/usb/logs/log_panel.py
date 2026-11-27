def info(self, text):

    self.logs.append(
        f"<span style='color:blue;'>[INFO]</span> {text}"
    )

def success(self, text):

    self.logs.append(
        f"<span style='color:green;'>[PASS]</span> {text}"
    )

def warning(self, text):

    self.logs.append(
        f"<span style='color:orange;'>[WARN]</span> {text}"
    )

def error(self, text):

    self.logs.append(
        f"<span style='color:red;'>[FAIL]</span> {text}"
    )