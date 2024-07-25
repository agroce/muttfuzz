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
INSTRUMENTATION_SET = ["__afl", "__asan", "__ubsan", "__sanitizer", "__lsan", "__sancov", "AFL_"]
INSTRUMENTATION_SET.extend(["DeepState", "deepstate"])

def sans_arguments(s):
    pos = len(s) - 1
    lcount = 0
    while pos > 0:
        if s[pos] == ")":
            lcount += 1
        if s[pos] == "(":
            if lcount > 1:
                lcount -= 1
            else:
                return s[:pos]
        pos -= 1
    return s

def get_jumps(filename, only_mutate=None, avoid_mutating=None, source_only_mutate=None, source_avoid_mutating=None,
              mutate_standard_libraries=False):
    if only_mutate is None:
        only_mutate = []
    if avoid_mutating is None:
        avoid_mutating = []
    if source_only_mutate is None:
        source_only_mutate = []
    if source_avoid_mutating is None:
        source_avoid_mutating = []

    jumps = {}
    function_map = {}
    function_reach = {}

    proc = subprocess.Popen(["objdump", "-d", "-C", "-l", "--file-offsets", filename],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = proc.communicate()
    output = str(out, encoding="utf-8")

    avoid = False
    first_inst = False

    last_source = ""
    source_avoid = False

    for line in output.split("\n"):
        try:
            if line[0] == "/" and ":" in line: # hit a line number
                last_source = line
                source_avoid = False

                for s in source_avoid_mutating:
                    if s in last_source:
                        source_avoid = True
                        break
                if source_only_mutate != []:
                    found = False
                    for s in source_only_mutate:
                        if s in last_source:
                            found = True
                            break
                    if not found:
                        source_avoid = True

            if "File Offset" in line and line[-1] == ":":
                avoid = False
                function_name = line.split(" ", 1)[1].split(" (File Offset", 1)[0]
                just_name = sans_arguments(function_name)
                just_name = just_name[1:]
                if not mutate_standard_libraries:
                    if "std::" in just_name:
                        avoid = True
                    if "boost::" in just_name:
                        avoid = True
                for s in avoid_mutating:
                    if s in just_name:
                        avoid = True
                        break
                if only_mutate != []:
                    found = False
                    for s in only_mutate:
                        if s in just_name:
                            found = True
                            break
                    if not found:
                        avoid = True
                base = int(line.split()[0], 16)
                offset_hex = line.split("File Offset:")[1].split(")")[0]
                offset = int(offset_hex, 16) - base
                first_inst = True
                continue
            if avoid:
                continue

            fields = line.split("\t")
            if len(fields) > 1:
                loc_bytes = fields[0].split(":")[0]
                loc = int(loc_bytes, 16) + offset

                if first_inst: # Record location of first instruction for function reachability purposes
                    # We need this EVEN if it's in STL/whatever, or is instrumentation
                    function_reach[function_name] = loc
                    first_inst = False

                if source_avoid:
                    continue

                found_instrumentation = False
                for i in INSTRUMENTATION_SET:
                    if i in line:
                        found_instrumentation = True
                        break
                if found_instrumentation:
                    continue # Don't mutate these things

                opcode = fields[2].split()[0]
                if opcode in JUMP_OPCODES:
                    loc_bytes = fields[0].split(":")[0]
                    loc = int(loc_bytes, 16) + offset
                    jumps[loc] = {"opcode": opcode,
                                  "hexdata": bytes.fromhex(fields[1]),
                                  "function_name": function_name,
                                  "source": last_source,
                                  "code": line}
                    if function_name not in function_map:
                        function_map[function_name] = [loc]
                    else:
                        function_map[function_name].append(loc)
        # If we can't parse the line, just ignore it
        except: #pylint: disable=W0702
            pass

    return (jumps, function_map, function_reach)

def different_jump(hexdata):
    P_FLIP = 0.70
    # First, just flip the jump condition 70% of the time
    if random.random() <= P_FLIP:
        if hexdata[0] == 15: # NEAR JUMP
            return NEAR_FLIP[hexdata[1]]
        return SHORT_FLIP[hexdata[0]]
    P_DC = 0.40 # P(Don't Care)
    P_DC_JMP = P_DC / (1 - P_DC)
    # Then change to "don't care" (take or avoid) 80% of time, mutate otherwise 20%
    if random.random() <= P_DC: # Just remove the jump by providing a NOP sled
        return NOP * len(hexdata)
    if hexdata[0] == 15: # NEAR JUMP BYTE CHECK
        if random.random() <= P_DC_JMP:
            return NEAR_JUMPS[-1]
        return random.choice(list(filter(lambda j: j[1] != hexdata[1], NEAR_JUMPS[:-1])))
    if random.random() <= P_DC_JMP:
        return SHORT_JUMPS[-1]
    return random.choice(list(filter(lambda j: j[0] != hexdata[0], SHORT_JUMPS[:-1])))

def pick_and_change(jumps, avoid_repeats=False, repeat_retries=20, visited_mutants=None, unreach_cache=None):
    if visited_mutants is None:
        visited_mutants = {}
    if unreach_cache is None:
        unreach_cache = {}
    done = False
    tries = 0
    while not done:
        tries += 1
        # First, pick a reachable jump
        reachable = False
        rtries = 0
        while not reachable:
            reachable = True
            rtries += 1
            if rtries > (len(jumps) * 10):
                print("SOMETHING IS WRONG, NEEDED MORE THAN", rtries, "ATTEMPTS TO FIND REACHABLE JUMP")
                raise RuntimeError("Unable to find reachable jump!")
            loc = random.choice(list(jumps.keys()))
            jump = jumps[loc]
            # Could know function is unreachable or specific jump is unreachable
            if jump["function_name"] in unreach_cache:
                reachable = False
            if loc in unreach_cache:
                reachable = False
        changed = different_jump(jump["hexdata"])
        if (not avoid_repeats) or ((loc, changed) not in visited_mutants):
            done = True
        if tries >= repeat_retries:
            print("WARNING: HAD TO USE REPEAT MUTANT DUE TO RUNNING OUT OF RETRIES")
            # Get all visited mutants and pick a random least-visited mutant
            all_visited = list(visited_mutants.keys())
            random.shuffle(all_visited)
            all_visited = sorted(all_visited, key=lambda x: visited_mutants[x])
            (loc, changed) = all_visited[0]
            jump = jumps[loc]
            done = True
    if (loc, changed) not in visited_mutants:
        visited_mutants[(loc, changed)] = 1
    else:
        visited_mutants[(loc, changed)] += 1
        print("VISITED THIS MUTANT", visited_mutants[(loc, changed)], "TIMES")

    print("MUTATING JUMP IN", jump["function_name"], "WITH ORIGINAL OPCODE", jump["opcode"])
    print("ORIGINAL CODE:", jump["code"])
    print("AT LINE:", jump["source"])
    if changed in SHORT_NAMES:
        print("CHANGING TO", SHORT_NAMES[changed])
    elif changed in NEAR_NAMES:
        print("CHANGING TO", NEAR_NAMES[changed])
    else:
        print("CHANGING TO NOPS")
    return (jump["function_name"], loc, changed)

def get_code(filename):
    with open(filename, "rb") as f:
        return bytearray(f.read())

def mutant_from(code, jumps, function_reach, order=1, avoid_repeats=False, repeat_retries=20, visited_mutants=None,
                unreach_cache=None):
    full_mutant_data = ""
    if visited_mutants is None:
        visited_mutants = {}
    if unreach_cache is None:
        unreach_cache = {}
    functions = []
    locs = []
    new_code = bytearray(code)
    reach_code = bytearray(code)
    func_reach_code = bytearray(code)
    for _ in range(order): # allows higher-order mutants, though can undo mutations
        (function, loc, new_data) = pick_and_change(jumps, avoid_repeats, repeat_retries, visited_mutants, unreach_cache)
        full_mutant_data += function + "\n"
        full_mutant_data += str(loc - function_reach[function]) + "\n"
        full_mutant_data += str(len(new_data)) + "\n"
        functions.append(function)
        locs.append(loc)
        func_reach_code[function_reach[function]] = HALT_OP
        for offset, data in enumerate(new_data):
            full_mutant_data += str(int(data)) + "\n"
            if offset == 0:
                reach_code[loc + offset] = HALT_OP
            else:
                reach_code[loc + offset] = NOP_OP
            new_code[loc + offset] = data
    return (functions, locs, new_code, full_mutant_data, reach_code, func_reach_code)

def write_files(mutant, full_mutant_data, reach, func_reach, new_filename, reachability_filename=None, func_reachability_filename=None,
                save_mutants=None, save_executables=False, save_count=0):
    with open(new_filename, "wb") as f:
        f.write(mutant)
    if save_mutants is not None:
        if save_executables:
            with open(save_mutants + "/mutant_" + str(save_count) + ".exe", "wb") as f:
                f.write(mutant)
        with open(save_mutants + "/mutant_" + str(save_count) + ".metadata", "w") as f:
            f.write(full_mutant_data)
    if reachability_filename is not None:
        with open(reachability_filename, "wb") as f:
            f.write(reach)
    if func_reachability_filename is not None:
        with open(func_reachability_filename, "wb") as f:
            f.write(func_reach)

def mutate_from(code, jumps, function_reach, new_filename, order=1, reachability_filename=None,
                func_reachability_filename=None, save_mutants=None, save_executables=False, save_count=0,
                avoid_repeats=False, repeat_retries=20,
                visited_mutants=None, unreach_cache=None):
    if visited_mutants is None:
        visited_mutants = {}
    if unreach_cache is None:
        unreach_cache = {}
    (functions, locs, new_mutant, full_mutant_data, new_reach, new_func_reach) = mutant_from(code, jumps, function_reach, order=order,
                                                                                             avoid_repeats=avoid_repeats,
                                                                                             repeat_retries=repeat_retries,
                                                                                             visited_mutants=visited_mutants,
                                                                                             unreach_cache=unreach_cache)
    write_files(new_mutant, full_mutant_data, new_reach, new_func_reach, new_filename, reachability_filename, func_reachability_filename,
                save_mutants, save_executables, save_count)
    return (functions, locs, full_mutant_data)

def apply_mutant_metadata(code, jumps, function_reach, metadata, new_executable):
    functions = []
    locs = []
    fields = metadata.split("\n")
    pos = 0
    new_code = bytearray(code)
    while (pos + 3) < len(fields):
        function = fields[pos]
        functions.append(function)
        loc = int(fields[pos + 1]) + function_reach[function]
        locs.append(loc)
        print("MUTATING JUMP IN", function, "WITH ORIGINAL OPCODE", jumps[loc]["opcode"])
        print("ORIGINAL CODE:", jumps[loc]["code"])
        data_len = int(fields[pos + 2])
        int_data = []
        new_pos = pos + 3
        for _ in range(data_len):
            int_data.append(int(fields[new_pos]))
            new_pos += 1
        pos = new_pos
        changed = bytes(int_data)
        if changed in SHORT_NAMES:
            print("CHANGING TO", SHORT_NAMES[changed])
        elif changed in NEAR_NAMES:
            print("CHANGING TO", NEAR_NAMES[changed])
        else:
            print("CHANGING TO NOPS")
        for offset, data in enumerate(changed):
            new_code[loc + offset] = data
    with open(new_executable, 'wb') as f:
        f.write(new_code)
    return (functions, locs, metadata)
