
class IndentationWriter(object):
    def __init__(self, indentation=0):
        self.indentation = indentation
        self.buf = ""

    def indent(self):
        self.indentation += 1

    def dedent(self):
        self.indentation -= 1

    def write(self, text):
        self.buf += self.indentation * "\t"
        self.buf += text

    def write_block(self, text):
        lines = text.split("\n")
        for line in lines:
            self.writeline(line)

    def writeline(self, text):
        self.write(text + "\n")

    def contents(self):
        return self.buf

    def clear(self):
        self.buf = ""
