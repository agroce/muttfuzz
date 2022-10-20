import random
import subprocess

JUMPS = ["je", "jne", "jl", "jle", "jg", "jge"]
SHORT_JUMPS = list(map(bytes.fromhex, ["74", "75", "7C", "7D", "7E", "7F"]))
NEAR_JUMPS = list(map(bytes.fromhex, ["0F 84", "0F 85", "0F 8C", "0F 8D", "0F 8E", "0F 8F"]))

def get_jumps(filename):
    jumps = {}

    proc = subprocess.Popen(["objdump", "-d", "--file-offsets", filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    output = str(out, encoding="utf-8")

    for line in output.split("\n"):
        if "File Offset" in line:
            offset_hex = line.split("File Offset:")[1].split(")")[0]
            section_offset = int(offset_hex, 16)
            print("SECTION OFFSET:", section_offset)
        fields = line.split("\t")
        if len(fields) > 1:
            opcode = fields[2].split()[0]
            if opcode in JUMPS:
                loc_bytes = fields[0].split(":")[0]
                loc = int(loc_bytes, 16)
                print("SECTION LOC:", loc)
                loc += section_offset
                jumps[loc] = (opcode, bytes.fromhex(fields[1]))            

    return jumps

def different_jump(hexdata):
    if hexdata[0] == 15: # NEAR JUMP BYTE CHECK
        return random.choice(list(filter(lambda j: j[1] != hexdata[1], NEAR_JUMPS)))
    else:
        return random.choice(list(filter(lambda j: j != hexdata[0], SHORT_JUMPS)))

def pick_and_change(jumps):
    loc = random.choice(list(jumps.keys()))
    return (loc, different_jump(jumps[loc][1]))

def get_code(filename):
    with open(filename, "rb") as f:
        return bytearray(f.read())

def mutant(filename):
    jumps = get_jumps(filename)
    code = get_code(filename)
    (loc, new_data) = pick_and_change(jumps)
    for offset in range(0, len(new_data)):
        code[loc + offset] = new_data[offset]
    return code
