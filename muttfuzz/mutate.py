import random
import subprocess

JUMP_OPCODES = ["je", "jne", "jl", "jle", "jg", "jge"]
SHORT_JUMPS = list(map(bytes.fromhex, ["74", "75", "7C", "7D", "7E", "7F", "EB"]))
# no unconditional for near jumps, since changes opcode length, not worth it
NEAR_JUMPS = list(map(bytes.fromhex, ["0F 84", "0F 85", "0F 8C", "0F 8D", "0F 8E", "0F 8F"]))

def get_jumps(filename):
    jumps = {}

    proc = subprocess.Popen(["objdump", "-d", "--file-offsets", filename],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    output = str(out, encoding="utf-8")

    for line in output.split("\n"):
        try:
            if "File Offset" in line and line[-1] == ":":
                offset_hex = line.split("File Offset:")[1].split(")")[0]
                section_offset = int(offset_hex, 16)
                use_offset = False
                continue
            if "__afl" in line:
                continue # heuristic to avoid mutating AFL instrumentation
            fields = line.split("\t")
            if len(fields) > 1:
                opcode = fields[2].split()[0]
                if opcode in JUMP_OPCODES:
                    loc_bytes = fields[0].split(":")[0]
                    loc = int(loc_bytes, 16)
                    if loc < section_offset:
                        use_offset = True
                    if use_offset:
                        loc += section_offset
                    jumps[loc] = (opcode, bytes.fromhex(fields[1]))
        except: # If we can't parse some line in the objdump, just skip it
            pass

    return jumps

def different_jump(hexdata):
    if hexdata[0] == 15: # NEAR JUMP BYTE CHECK
        return random.choice(list(filter(lambda j: j[1] != hexdata[1], NEAR_JUMPS)))
    else:
        return random.choice(list(filter(lambda j: j[0] != hexdata[0], SHORT_JUMPS)))

def pick_and_change(jumps):
    loc = random.choice(list(jumps.keys()))
    return (loc, different_jump(jumps[loc][1]))

def get_code(filename):
    with open(filename, "rb") as f:
        return bytearray(f.read())

def mutant_from(code, jumps, order=1):
    new_code = bytearray(code)
    for i in range(order): # allows higher-order mutants, though can undo mutations
        (loc, new_data) = pick_and_change(jumps)
        for offset in range(0, len(new_data)):
            new_code[loc + offset] = new_data[offset]
    return new_code

def mutant(filename, order=1):
    return mutant_from(get_code(filename), get_jumps(filename), order=order)

def mutate_from(code, jumps, new_filename, order=1):
    with open(new_filename, 'wb') as f:
        f.write(mutant_from(code, jumps, order=order))

def mutate(filename, new_filename, order=1):
    with open(new_filename, "wb") as f:
        f.write(mutant(filename, order=order))
