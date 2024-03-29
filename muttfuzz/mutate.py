import random
import subprocess

JUMP_OPCODES = ["je", "jne", "jl", "jle", "jg", "jge"]
SHORT_JUMPS = list(map(bytes.fromhex, ["74", "75", "7C", "7D", "7E", "7F", "EB"]))
# no unconditional for near jumps, since changes opcode length, not worth it
NEAR_JUMPS = list(map(bytes.fromhex, ["0F 84", "0F 85", "0F 8C", "0F 8D", "0F 8E", "0F 8F", "90 E9"]))

# known markers for fuzzer/compiler injected instrumentation/etc.
INST_SET = ["__afl", "__asan", "__ubsan", "__sanitizer", "__lsan", "__sancov", "AFL_"]
INST_SET.extend(["DeepState", "deepstate"])

def get_jumps(filename):
    jumps = {}

    proc = subprocess.Popen(["objdump", "-d", "--file-offsets", filename],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    output = str(out, encoding="utf-8")

    for line in output.split("\n"):
        try:
            if "File Offset" in line and line[-1] == ":":
                section_base = int(line.split()[0], 16)
                offset_hex = line.split("File Offset:")[1].split(")")[0]
                section_offset = int(offset_hex, 16) - section_base
                continue
            found_inst = False
            for i in INST_SET:
                if i in line:
                    found_inst = True
                    break
            if found_inst:
                continue # Don't mutate these things
            fields = line.split("\t")
            if len(fields) > 1:
                opcode = fields[2].split()[0]
                if opcode in JUMP_OPCODES:
                    loc_bytes = fields[0].split(":")[0]
                    loc = int(loc_bytes, 16) + section_offset
                    jumps[loc] = (opcode, bytes.fromhex(fields[1]))
        except: # If we can't parse some line in the objdump, just skip it
            pass

    return jumps

def different_jump(hexdata):
    if hexdata[0] == 15: # NEAR JUMP BYTE CHECK
        # Have a high chance of just changing near JE and JNE to a forced JMP, "removing" a branch
        if ((hexdata[1] == NEAR_JUMPS[0][1])  or (hexdata[1] == NEAR_JUMPS[1][1])) and (random.random() <= 0.75):
            return NEAR_JUMPS[-1]
        return random.choice(list(filter(lambda j: j[1] != hexdata[1], NEAR_JUMPS)))
    else:
        # Have a high chance of just changing short JE and JNE to a forced JMP, "removing" a branch
        if ((hexdata[0] == SHORT_JUMPS[0][0])  or (hexdata[0] == SHORT_JUMPS[1][0])) and (random.random() <= 0.75):
            return SHORT_JUMPS[-1]
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
