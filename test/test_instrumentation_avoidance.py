"""Tests for issue #1: avoid mutating all code inside INST_SET related blocks.

These tests mock out objdump with a crafted disassembly so we can verify that
mutate.get_jumps() correctly skips every jump inside a function whose name
matches INSTRUMENTATION_SET, while still recording jumps in unrelated
functions. They also check that the original line-level instrumentation
filter keeps working.
"""

from unittest.mock import patch, MagicMock

from muttfuzz import mutate


def _fake_objdump(output_text):
    """Return a MagicMock that mimics subprocess.Popen for objdump."""
    proc = MagicMock()
    proc.communicate.return_value = (output_text.encode("utf-8"), b"")
    return proc


# Crafted objdump-style output. Three functions:
#   - normal_function      -> should be mutated
#   - __afl_maybe_log      -> should be SKIPPED (matches "__afl")
#   - DeepState_Run        -> should be SKIPPED (matches "DeepState")
OBJDUMP_OUTPUT = (
    "\n"
    "Disassembly of section .text:\n"
    "\n"
    "0000000000401000 <normal_function> (File Offset: 0x1000):\n"
    "  401000:\t74 05                \tje     401007 <normal_function+0x7>\n"
    "  401002:\t90                   \tnop\n"
    "  401003:\teb 03                \tjmp    401008 <normal_function+0x8>\n"
    "\n"
    "0000000000401100 <__afl_maybe_log> (File Offset: 0x1100):\n"
    "  401100:\t75 0a                \tjne    40110c <next_helper>\n"
    "  401102:\t7c 04                \tjl     401108 <next_helper>\n"
    "\n"
    "0000000000401200 <DeepState_Run> (File Offset: 0x1200):\n"
    "  401200:\t74 08                \tje     401208 <some_other_label>\n"
    "  401202:\t7d 02                \tjge    401206 <some_other_label>\n"
)


def test_instrumentation_function_names_are_fully_skipped():
    """No jump inside __afl_* or DeepState_* functions should appear."""
    with patch("muttfuzz.mutate.subprocess.Popen",
               return_value=_fake_objdump(OBJDUMP_OUTPUT)):
        jumps, function_map, _ = mutate.get_jumps("dummy_binary")

    recorded_functions = {j["function_name"] for j in jumps.values()}
    for fn in recorded_functions:
        assert "__afl" not in fn, (
            "Regression on issue #1: __afl_* function should be fully "
            "skipped but produced jumps: %r" % fn
        )
        assert "DeepState" not in fn, (
            "Regression on issue #1: DeepState_* function should be fully "
            "skipped but produced jumps: %r" % fn
        )
    assert any("normal_function" in fn for fn in recorded_functions), (
        "normal_function jumps should still be collected after the fix"
    )
    # function_map should also exclude instrumentation functions
    for fn in function_map:
        assert "__afl" not in fn and "DeepState" not in fn


def test_normal_function_jumps_are_preserved():
    """Non-instrumentation functions must still produce mutable jumps."""
    with patch("muttfuzz.mutate.subprocess.Popen",
               return_value=_fake_objdump(OBJDUMP_OUTPUT)):
        jumps, _, _ = mutate.get_jumps("dummy_binary")
    # normal_function has two jumps in the fixture: je at 0x401000 and
    # jmp at 0x401003. Since jmp (eb) is not in JUMP_OPCODES, only je
    # is recorded. Assert at least one jump survives.
    assert len(jumps) >= 1
    for j in jumps.values():
        assert "normal_function" in j["function_name"]


def test_line_level_instrumentation_filter_still_works():
    """Regression: a non-instrumentation function containing a jump that
    targets an __afl_* label should still have that single line filtered
    out (preserving the previous behavior)."""
    mixed_output = (
        "0000000000402000 <user_function> (File Offset: 0x2000):\n"
        "  402000:\t74 05                \tje     402007 <__afl_trampoline>\n"
        "  402002:\t75 03                \tjne    402007 <user_function+0x7>\n"
    )
    with patch("muttfuzz.mutate.subprocess.Popen",
               return_value=_fake_objdump(mixed_output)):
        jumps, _, _ = mutate.get_jumps("dummy_binary")
    # One jump should survive: the jne that does not reference __afl.
    # The je whose target label mentions __afl_trampoline must be skipped.
    assert len(jumps) == 1, (
        "Expected exactly one jump; line-level filter or function-level "
        "filter is misbehaving: %r" % jumps
    )
    remaining = list(jumps.values())[0]
    assert remaining["opcode"] == "jne"
    assert "user_function" in remaining["function_name"]


def test_user_avoid_mutating_still_works():
    """The existing --avoid_mutating feature must continue working unchanged."""
    output = (
        "0000000000403000 <keep_me> (File Offset: 0x3000):\n"
        "  403000:\t74 05                \tje     403007 <keep_me+0x7>\n"
        "\n"
        "0000000000403100 <skip_me_please> (File Offset: 0x3100):\n"
        "  403100:\t74 05                \tje     403107 <skip_me_please+0x7>\n"
    )
    with patch("muttfuzz.mutate.subprocess.Popen",
               return_value=_fake_objdump(output)):
        jumps, _, _ = mutate.get_jumps("dummy_binary",
                                       avoid_mutating=["skip_me"])
    recorded = {j["function_name"] for j in jumps.values()}
    assert any("keep_me" in fn for fn in recorded)
    assert not any("skip_me" in fn for fn in recorded)


if __name__ == "__main__":
    # Allow `python test_instrumentation_avoidance.py` without pytest
    test_instrumentation_function_names_are_fully_skipped()
    test_normal_function_jumps_are_preserved()
    test_line_level_instrumentation_filter_still_works()
    test_user_avoid_mutating_still_works()
    print("All tests passed.")
