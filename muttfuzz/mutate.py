import random
import subprocess

JUMP_OPCODES = ["je", "jne", "jl", "jle", "jg", "jge"]
SHORT_JUMPS = list(map(bytes.fromhex, ["74", "75", "7C", "7D", "7E", "7F", "EB"]))
SHORT_NAMES = dict(zip(SHORT_JUMPS, ["je", "jne", "jl", "jge", "jle", "jg", "jmp"]))
SHORT_OPPOSITES = list(map(bytes.fromhex, ["75", "74", "7D", "7C", "7F", "7E"]))
SHORT_FLIP = dict(zip(map(lambda x: x[0], SHORT_JUMPS[:-1]), SHORT_OPPOSITES))
NEAR_JUMPS = list(map(bytes.fromhex, ["0F 84", "0F 85", "0F 8C", "0F 8D", "0F 8E", "0F 8F", "90 E9"]))
NEAR_NAMES = dict(zip(NEAR_JUMPS, ["je", "jne", "jl", "jge", "jle", "jg", "jmp"]))
NEAR_OPPOSITES = list(map(bytes.fromhex, ["0F 85", "0F 84", "0F 8D", "0F 8C", "0F 8F", "0F 8E"]))
NEAR_FLIP = dict(zip(map(lambda x: x[1], NEAR_JUMPS[:-1]), NEAR_OPPOSITES))

NOP = bytes.fromhex("90") # Needed to erase a jump
NOP_OP = NOP[0]
HALT = bytes.fromhex("F4") # Needed for reachability check
HALT_OP = HALT[0]

# known markers for fuzzer/compiler injected instrumentation/etc.
INST_SET = ["__afl", "__asan", "__ubsan", "__sanitizer", "__lsan", "__sancov", "AFL_"]
INST_SET.extend(["DeepState", "deepstate"])

def get_jumps(filename, only_mutate=[], avoid_mutating=[]):
    jumps = {}

    proc = subprocess.Popen(["objdump", "-d", "--file-offsets", filename],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    output = str(out, encoding="utf-8")

    avoid = False

    for line in output.split("\n"):
        try:
            if "File Offset" in line and line[-1] == ":":
                avoid = False
                section_name = line.split()[1]
                for s in avoid_mutating:
                    if s in section_name:
                        avoid = True
                        break
                if only_mutate != []:
                    found = False
                    for s in only_mutate:
                        if s in section_name:
                            found = True
                            break
                    if not found:
                        avoid = True
                section_base = int(line.split()[0], 16)
                offset_hex = line.split("File Offset:")[1].split(")")[0]
                section_offset = int(offset_hex, 16) - section_base
                continue
            if avoid:
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
                    jumps[loc] = {"opcode": opcode,
                                  "hexdata": bytes.fromhex(fields[1]),
                                  "section_name": section_name,
                                  "code": line}
        except: # If we can't parse some line in the objdump, just skip it
            pass

    return jumps

def different_jump(hexdata):
    P_FLIP = 0.70
    # First, just flip the jump condition 70% of the time
    if (random.random() <= P_FLIP):
        if hexdata[0] == 15: # NEAR JUMP
            return NEAR_FLIP[hexdata[1]]
        else:
            return SHORT_FLIP[hexdata[0]]
    P_DC = 0.40 # P(Don't Care)
    P_DC_JMP = P_DC / (1 - P_DC)
    # Then change to "don't care" (take or avoid) 80% of time, mutate otherwise 20%
    if (random.random() <= P_DC): # Just remove the jump by providing a NOP sled
        return NOP * len(hexdata)
    if hexdata[0] == 15: # NEAR JUMP BYTE CHECK
        if random.random() <= P_DC_JMP:
            return NEAR_JUMPS[-1]
        return random.choice(list(filter(lambda j: j[1] != hexdata[1], NEAR_JUMPS[:-1])))
    else:
        if random.random() <= P_DC_JMP:
            return SHORT_JUMPS[-1]
        return random.choice(list(filter(lambda j: j[0] != hexdata[0], SHORT_JUMPS[:-1])))

def pick_and_change(jumps):
    loc = random.choice(list(jumps.keys()))
    jump = jumps[loc]
    changed = different_jump(jump["hexdata"])
    print("MUTATING JUMP IN", jump["section_name"], "WITH ORIGINAL OPCODE", jump["opcode"])
    print("ORIGINAL CODE:", jump["code"])
    if changed in SHORT_NAMES:
        print("CHANGING TO", SHORT_NAMES[changed])
    elif changed in NEAR_NAMES:
        print("CHANGING TO", NEAR_NAMES[changed])
    else:
        print("CHANGING TO NOPS")
    full_change = bytearray(jump["hexdata"]) # lets us write the correct set of NOPs for HALT insertion
    for i in range(len(changed)):
        full_change[i] = changed[i]
    return (jump["section_name"], loc, changed)

def get_code(filename):
    with open(filename, "rb") as f:
        return bytearray(f.read())

def mutant_from(code, jumps, order=1):
    sections = []
    new_code = bytearray(code)
    reach_code = bytearray(code)
    for i in range(order): # allows higher-order mutants, though can undo mutations
        (section, loc, new_data) = pick_and_change(jumps)
        sections.append(section)
        for offset in range(0, len(new_data)):
            if offset == 0:
                reach_code[loc + offset] = HALT_OP
            else:
                reach_code[loc + offset] = NOP_OP
            new_code[loc + offset] = new_data[offset]
    return (sections, new_code, reach_code)

def mutant(filename, order=1, avoid_mutating=[]):
    return mutant_from(get_code(filename), get_jumps(filename, avoid_mutating), order=order)

def write_files(mutant, reach, new_filename, reachability_filename="", save_mutants="", save_count=0):
    with open(new_filename, "wb") as f:
        f.write(mutant)
    if save_mutants != "":
        with open(save_mutants + "/mutant_" + str(save_count), "wb") as f:
            f.write(mutant)
    if reachability_filename != "":
        with open(reachability_filename, "wb") as f:
            f.write(reach)
        if save_mutants != "":
            with open(save_mutants + "/reach_" + str(save_count), "wb") as f:
                f.write(reach)

def mutate_from(code, jumps, new_filename, order=1, reachability_filename="", save_mutants="", save_count=0):
    (sections, mutant, reach) = mutant_from(code, jumps, order=order)
    write_files(mutant, reach, new_filename, reachability_filename, save_mutants, save_count)
    return sections

def mutate(filename, new_filename, order=1, avoid_mutating=[], reachability_filename="", save_mutants="", save_count=0):
    (sections, mutant, reach) = mutant(filename, order=order, avoid_mutating=avoid_mutating)
    write_files(mutant, reach, new_filename, reachability_filename, save_mutants, save_count)
    return sections
