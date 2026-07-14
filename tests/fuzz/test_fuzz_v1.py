from __future__ import annotations

import json
import random
import string
import unittest

from mcp_tool_card_linter.lint import lint_sources
from mcp_tool_card_linter.models import LintConfig, SourceResult, ToolCard
from mcp_tool_card_linter.reporting import report_to_json
from mcp_tool_card_linter.security import InputValidationError, strict_json_loads


class DeterministicFuzzV1Tests(unittest.TestCase):
    def test_json_parser_round_trips_random_bounded_values_and_rejects_extensions(self) -> None:
        randomizer = random.Random(0x4D435031)
        for _ in range(500):
            value = _json_value(randomizer, depth=0)
            encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
            self.assertEqual(strict_json_loads(encoded), value)
        for invalid in (
            '{"a":1,"a":2}',
            '{"n":NaN}',
            '{"n":Infinity}',
            '{"n":-Infinity}',
            '{"unterminated":',
        ):
            with self.assertRaises(InputValidationError):
                strict_json_loads(invalid)

    def test_mutated_tool_shapes_always_produce_bounded_serializable_reports(self) -> None:
        randomizer = random.Random(0x544F4F4C)
        for index in range(300):
            raw = _json_value(randomizer, depth=0)
            if isinstance(raw, dict):
                raw[randomizer.choice(["name", "description", "inputSchema", "annotations"])] = _json_value(
                    randomizer, depth=1
                )
            card = ToolCard.from_raw(raw, server_name="fuzz", index=index)
            report = lint_sources(
                [SourceResult("fuzz", "deterministic-fuzz", [card])],
                LintConfig(max_schema_depth=8, max_schema_properties=100),
                deterministic=True,
            )
            encoded = report_to_json(report)
            self.assertLess(len(encoded), 2 * 1024 * 1024)
            self.assertEqual(json.loads(encoded)["summary"]["tools_scanned"], 1)


def _json_value(randomizer: random.Random, *, depth: int):
    choices = ["null", "bool", "int", "float", "str"]
    if depth < 4:
        choices.extend(["list", "dict"])
    kind = randomizer.choice(choices)
    if kind == "null":
        return None
    if kind == "bool":
        return bool(randomizer.getrandbits(1))
    if kind == "int":
        return randomizer.randint(-(2**31), 2**31)
    if kind == "float":
        return randomizer.uniform(-1_000_000, 1_000_000)
    if kind == "str":
        alphabet = string.ascii_letters + string.digits + " _-./" + "\u202e\u200b"
        return "".join(randomizer.choice(alphabet) for _ in range(randomizer.randrange(80)))
    if kind == "list":
        return [_json_value(randomizer, depth=depth + 1) for _ in range(randomizer.randrange(5))]
    return {
        f"k{depth}_{index}": _json_value(randomizer, depth=depth + 1)
        for index in range(randomizer.randrange(5))
    }


if __name__ == "__main__":
    unittest.main()
