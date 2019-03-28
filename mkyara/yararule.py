from .indentwriter import IndentationWriter
import collections


class StringType(object):
    STRING = 1
    HEX = 2
    REGEX = 3


class YaraString(object):
    def __init__(self, key, value, string_type=StringType.STRING):
        self.string_type = string_type
        self.value = value
        self.key = key


class YaraRule(object):
    def __init__(self):
        self._writer = IndentationWriter(0)
        self.is_global = False
        self.is_private = False
        self.rule_name = ""
        self.strings = []
        self.condition = ""
        self.metas = collections.OrderedDict()
        self.tags = []
        self.comments = []

    def add_string(self, key, value, string_type=StringType.STRING):
        s = YaraString(key, value, string_type=string_type)
        self.strings.append(s)

    def _generate_rule_header(self):
        """ Generate Rule header """
        result = ""
        modifiers = []
        if self.is_private:
            modifiers.append("private")
        if self.is_global:
            modifiers.append("global")
        result += " ".join(modifiers)
        tag_str = ' '.join(self.tags)
        result += " rule {}".format(self.rule_name)
        if len(self.tags) > 0:
            result += " : {}".format(tag_str)

        result = result.strip()
        self._writer.writeline(result)

    def _generate_meta_section(self):
        """ Generate rule meta section """
        if len(self.metas) > 0:
            self._writer.writeline("meta:")
            self._writer.indent()
            for key in self.metas:
                value = self.metas[key]
                self._writer.writeline("{} = {}".format(key, value))
            self._writer.dedent()
            self._writer.writeline("")

    def _generate_comments_section(self):
        """ Generate a section with the comments """
        if len(self.comments) > 0:
            for comment_txt in self.comments:
                comment = "/*\n{} */".format(comment_txt)
                self._writer.write_block(comment)

    def _generate_strings_section(self):
        """ Generate strings section """
        self._writer.writeline("strings:")
        self._writer.indent()
        for s in self.strings:
            if s.string_type == StringType.STRING:
                self._writer.writeline('{} = "{}"'.format(s.key, s.value))
            elif s.string_type == StringType.HEX:
                self._writer.writeline('{} = {{'.format(s.key, s.value))
                self._writer.indent()
                value = s.value.rstrip('\n')
                self._writer.write_block(value)
                self._writer.dedent()
                self._writer.writeline("}")
            else:
                raise Exception("not implemented!")
        self._writer.dedent()
        self._writer.writeline("")

    def _generate_condition_section(self):
        """ Generate rule condition """
        self._writer.writeline("condition:")
        self._writer.indent()
        self._writer.writeline(self.condition)
        self._writer.dedent()
        self._writer.writeline("")

    def get_rule_string(self):
        """ Get the string representation of the rule """
        self._writer.clear()
        self._generate_rule_header()
        self._writer.writeline("{")
        self._writer.indent()

        self._generate_meta_section()
        self._generate_comments_section()
        self._generate_strings_section()
        self._generate_condition_section()

        self._writer.dedent()
        self._writer.writeline("}")
        return self._writer.contents()


if __name__ == "__main__":
    yr = YaraRule()
    yr.rule_name = "test"
    yr.tags.append("test_tag")
    yr.tags.append("test_tag2")
    yr.metas["version"] = "1.0"
    yr.add_string("$a", "lalalalala")
    yr.add_string("$b", "AA BB CC\nAA BB CC DD", string_type=StringType.HEX)
    yr.condition = "$a"
    yr.is_private = True
    yr.is_global = True
    print(yr.get_rule_string())
