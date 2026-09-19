"""ETH / token flow predicates."""

from __future__ import annotations

from detector.analysis.flows import is_whole_pot, token_out_calls, value_sends
from tests.detector.analysis_util import fn, tier1_ctx


def test_value_sends_whole_pot(slither_for) -> None:
    sweep = tier1_ctx(slither_for, "LEAK_PRIV_SWEEP", "mal")
    sends = value_sends(fn(sweep, "emergencyWithdraw"))
    assert len(sends) == 1
    node, _to, value, kind = sends[0]
    assert kind == "transfer"
    assert is_whole_pot(value, fn(sweep, "emergencyWithdraw")) is True
    _ = node

    honey_mal = tier1_ctx(slither_for, "HONEYPOT_LEGACY", "mal")
    withdraw = fn(honey_mal, "withdraw")
    sends_h = value_sends(withdraw)
    assert sends_h
    assert is_whole_pot(sends_h[0][2], withdraw) is True

    honey_ben = tier1_ctx(slither_for, "HONEYPOT_LEGACY", "ben")
    withdraw_b = fn(honey_ben, "withdraw")
    sends_b = value_sends(withdraw_b)
    assert sends_b
    assert is_whole_pot(sends_b[0][2], withdraw_b) is False


def test_token_out_calls(slither_for) -> None:
    rescue = tier1_ctx(slither_for, "LEAK_PRIV_SWEEP", "ben")
    outs = token_out_calls(fn(rescue, "rescueERC20"), rescue.bindings)
    assert outs
    assert any(source == "param" for _, _, source, _, _ in outs)

    drain = tier1_ctx(slither_for, "DRAIN_APPROVAL_PULL", "mal")
    claim = token_out_calls(fn(drain, "claim"), drain.bindings)
    assert any(source == "state" for _, ir, source, _, _ in claim if str(ir.function_name) == "transferFrom")
