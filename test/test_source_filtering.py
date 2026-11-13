"""Tests for source/debug-info based filtering in mutate.get_jumps().

Line-number state must not leak from one function into the next: a function
without line info that follows a target function used to inherit that
function's source location, so --source_only_mutate let sanitizer/fuzzer
runtime code through. Uses a crafted objdump listing (no real binary needed).
"""

from unittest.mock import patch, MagicMock

from muttfuzz import mutate


def _fake_objdump(output_text):
    proc = MagicMock()
    proc.communicate.return_value = (output_text.encode("utf-8"), b"")
    return proc


OBJDUMP_OUTPUT = (
    "\n"
    "Disassembly of section .text:\n"
    "\n"
    # runtime code with no line info, BEFORE any target code
    "0000000000401000 <format_get_value_size(char, char const*, bool)> (File Offset: 0x1000):\n"
    "  401000:\t74 05                \tje     401007 <format_get_value_size+0x7>\n"
    "\n"
    "0000000000401100 <target_parse> (File Offset: 0x1100):\n"
    "target_parse():\n"
    "/src/target/parse.c:10\n"
    "  401100:\t75 0a                \tjne    40110c <target_parse+0xc>\n"
    "\n"
    # runtime code with no line info, AFTER target code
    "0000000000401200 <ioctl_table_fill()> (File Offset: 0x1200):\n"
    "  401200:\t74 08                \tje     401208 <ioctl_table_fill+0x8>\n"
    "\n"
    # AFL++ runtime that was compiled with debug info
    "0000000000401300 <at_exit> (File Offset: 0x1300):\n"
    "at_exit():\n"
    "/opt/AFLplusplus/instrumentation/afl-compiler-rt.o.c:602\n"
    "  401300:\t74 08                \tje     401308 <at_exit+0x8>\n"
    "\n"
    # ASan check thunk and AFL++ cmplog runtime
    "0000000000401400 <.check_load_add_1_RAX> (File Offset: 0x1400):\n"
    "  401400:\t74 08                \tje     401408 <.check_load_add_1_RAX+0x8>\n"
    "\n"
    "0000000000401500 <cmplog_rtn_strn> (File Offset: 0x1500):\n"
    "  401500:\t74 08                \tje     401508 <cmplog_rtn_strn+0x8>\n"
    "\n"
    "0000000000401600 <target_helper> (File Offset: 0x1600):\n"
    "target_helper():\n"
    "/src/target/helper.c:5\n"
    "  401600:\t7c 04                \tjl     401606 <target_helper+0x6>\n"
)


def _functions(**kwargs):
    with patch("muttfuzz.mutate.subprocess.Popen", return_value=_fake_objdump(OBJDUMP_OUTPUT)):
        jumps, _function_map, function_reach = mutate.get_jumps("dummy_binary", **kwargs)
    return {j["function_name"] for j in jumps.values()}, jumps, function_reach


def test_default_skips_known_runtime_markers():
    funcs, _, _ = _functions()
    assert not any(".check_load" in f for f in funcs)
    assert not any("cmplog_" in f for f in funcs)
    assert "<at_exit>" not in funcs  # source file is the AFL++ runtime
    assert "<target_parse>" in funcs and "<target_helper>" in funcs


def test_source_only_mutate_does_not_leak_into_functions_without_line_info():
    funcs, _, _ = _functions(source_only_mutate=["/src/target/"])
    assert funcs == {"<target_parse>", "<target_helper>"}


def test_debug_info_only():
    funcs, _, _ = _functions(debug_info_only=True)
    assert funcs == {"<target_parse>", "<target_helper>"}


def test_jumps_without_line_info_have_empty_source():
    _, jumps, _ = _functions()
    for j in jumps.values():
        if "ioctl_table_fill" in j["function_name"]:
            assert j["source"] == ""


def test_function_reach_still_recorded_for_skipped_functions():
    # reachability needs function entry points even for functions that are not mutated
    _, _, function_reach = _functions(source_only_mutate=["/src/target/"])
    assert "<ioctl_table_fill()>" in function_reach
