from __future__ import print_function
from mkyara import (
    YaraGenerator,
)
from capstone import (
    CS_ARCH_X86,
    CS_MODE_32,
    CS_MODE_64,
)
import binascii
import sys
import yara
import argparse
import logging
import hashlib

log = logging.getLogger(__package__)


INSTRUCTION_SET_MAPPING = {
    'x86': CS_ARCH_X86,
}
INSTRUCTION_MODE_MAPPING = {
    '32': CS_MODE_32,
    '64': CS_MODE_64,
    'x86': CS_MODE_32,
    'x64': CS_MODE_64,
}


def auto_int(x):
    return int(x, 0)


def sha256_hash(path):
    m = hashlib.sha256()
    f = open(path, "rb")
    while True:
        data = f.read(4096)
        if not data:
            break
        m.update(data)
    return m.hexdigest()


def main():
    instr_set_keys = list(INSTRUCTION_SET_MAPPING.keys())
    instr_mode_keys = list(INSTRUCTION_MODE_MAPPING.keys())
    parser = argparse.ArgumentParser(description='Generate a Yara rule based on disassembled code', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-i', '--instruction_set', type=str, help='Instruction set', choices=instr_set_keys, default=instr_set_keys[0])
    parser.add_argument('-a', '--instruction_mode', type=str, help='Instruction mode', choices=instr_mode_keys, default=instr_mode_keys[0])

    parser.add_argument('-f', '--file_path', type=str, help='Sample file path', required=True)
    parser.add_argument('-n', '--rulename', type=str, help='Generated rule name', default="generated_rule")
    parser.add_argument('-o', '--offset', type=auto_int, help='File offset for signature', required=True)
    parser.add_argument('-s', '--size', type=auto_int, help='Size of desired signature', required=True)
    parser.add_argument('-m', '--mode', type=str, help="""Wildcard mode for yara rule generation\nloose = wildcard all operands\nnormal = wildcard only displacement operands\nstrict = wildcard only jmp/call addresses""", required=False, choices=["loose", "normal", "strict"], default="normal")
    parser.add_argument('-r', '--result', type=argparse.FileType('w'), help='Output file', required=False, default=None)
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")
    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels) - 1, args.verbose)]
    logging.basicConfig(stream=sys.stderr, level=level, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    log.info("Disassembling code and generating signature...")
    ins_set = INSTRUCTION_SET_MAPPING[args.instruction_set]
    ins_mode = INSTRUCTION_MODE_MAPPING[args.instruction_mode]
    yr_gen = YaraGenerator(args.mode, ins_set, ins_mode, rule_name=args.rulename)
    with open(args.file_path, 'rb') as file:
        file.seek(args.offset)
        data = file.read(args.size)
        yr_gen.add_chunk(data, args.offset)

    yr_rule = yr_gen.generate_rule()
    yr_rule.metas["sample"] = "\"{}\"".format(sha256_hash(args.file_path))

    log.info("Creating Yara rule...")
    yr_rule_str = yr_rule.get_rule_string()

    out_file = args.result or sys.stdout
    log.info("Writing to output file...")
    out_file.write(yr_rule_str)

    log.info("Checking generated rule...")
    compiled_yr = yara.compile(source=yr_rule_str)
    matches = compiled_yr.match(args.file_path)
    if len(matches) == 0:
        log.info("ERROR! Generated rule does not match on source file.")
    else:
        log.info("Rule check OK. Source file matches on rule!")
        for match in matches:
            log.debug("Sample matched rule {}".format(match))
            for s in match.strings:
                hex_bytes = binascii.hexlify(s[2])
                hex_bytes = hex_bytes.decode("ascii")
                log.debug("0x{:X} - {}\t {}".format(s[0], s[1], hex_bytes))


if __name__ == "__main__":
    main()
