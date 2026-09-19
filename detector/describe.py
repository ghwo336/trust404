"""Human-readable titles and one-line explanations for rule ids, families and reason codes.

Reporting only: nothing here is used to match identifiers in analysed source. Keys mirror
baybench/catalog.yaml (tests assert identity); summary.md and README.md render from this table.
"""

from __future__ import annotations

from detector.model import Finding

FAMILY_TITLES: dict[str, str] = {
    "A": "Exit gating",
    "B": "Balance tamper",
    "C": "Fund extraction",
    "D": "Control-plane deception",
    "E": "Structural escape hatches",
    "F": "Approval drainers and honeypots",
    "G": "Ponzi schemes",
}

# Short human name per rule id. Titles contain no commas or pipes (they are joined into
# sentences and rendered in markdown table cells).
RULE_TITLES: dict[str, str] = {
    # A — exit gating
    "PRIV_ROLE": "Role-gated function",
    "EXIT_ADDR_GATE": "Settable address gate on transfers",
    "EXIT_GLOBAL_SWITCH": "Privileged global transfer switch",
    "EXIT_AMOUNT_LIMIT": "Privileged transfer amount limit",
    "EXIT_TIME_GATE": "Privileged time gate on transfers",
    "EXIT_SELL_ONLY": "Sell-only gate via a settable address",
    "EXIT_CALLBACK_CYCLE": "Callback cycle re-entering a transfer gate",
    "FEE_UNBOUNDED": "Uncapped privileged fee",
    # B — balance tamper
    "BAL_PRIV_MINT": "Privileged mint",
    "BAL_PRIV_BURN_OTHER": "Privileged burn of another account",
    "BAL_DIRECT_SET": "Privileged direct balance write",
    "BAL_TRANSFER_HIDDEN_MINT": "Hidden mint inside transfer",
    "VIEW_CALLER_DEPENDENT": "Caller-dependent balanceOf or totalSupply",
    # C — fund extraction
    "FEE_ADDR_MUTABLE": "Settable fee recipient",
    "LEAK_ARBITRARY_TRANSFERFROM": "Privileged transfer from any account without allowance",
    "LEAK_EXEMPT_PATH": "Privileged transfer path skipping the sender debit",
    "LEAK_PRIV_SWEEP": "Privileged sweep of custodied funds",
    "SLITHER_HIGH_OVERLAY": "Slither high-impact check",
    # D — control-plane deception
    "OWN_HIDDEN_ROLE": "Undisclosed privileged role",
    "OWN_FAKE_RENOUNCE": "Renouncement that keeps a privileged role alive",
    "OWN_REASSIGN_NONSTD": "Non-standard reassignment of a privileged role",
    "OWN_TX_ORIGIN": "tx.origin-based authorisation",
    # E — structural escape hatches
    "STRUCT_EXTERNAL_GATE": "Transfer logic delegated to a settable external contract",
    "STRUCT_DELEGATECALL_SETTABLE": "delegatecall to a settable address",
    "STRUCT_SELFDESTRUCT": "Reachable selfdestruct",
    "STRUCT_PROXY_EOA_ADMIN": "Upgradeable proxy with a single-key admin",
    # F — drainers and honeypots
    "DRAIN_APPROVAL_PULL": "Approval drainer pulling caller funds to a third party",
    "HONEYPOT_LEGACY": "Legacy honeypot exit condition",
    # G — ponzi
    "PONZI_SHAPE": "Ponzi payout shape",
}

# One sentence per rule: what structural fact fired and why it matters to a token holder.
RULE_EXPLANATIONS: dict[str, str] = {
    "PRIV_ROLE": (
        "A function is reachable only when msg.sender or tx.origin matches a stored address or "
        "an address-to-bool map; evidence for the other rules, never a verdict on its own."
    ),
    "EXIT_ADDR_GATE": (
        "An address-to-bool map that a privileged role can write is read in a require/revert "
        "on the transfer path: the role can freeze individual holders."
    ),
    "EXIT_GLOBAL_SWITCH": (
        "A privileged-writable bool gates the transfer path: the role can halt all transfers."
    ),
    "EXIT_AMOUNT_LIMIT": (
        "A privileged-writable number is compared with the transfer amount in a require: the "
        "role can shrink the limit until nobody can exit."
    ),
    "EXIT_TIME_GATE": (
        "A privileged-writable timestamp or block number gates the transfer path: the role "
        "controls when transfers are allowed."
    ),
    "EXIT_SELL_ONLY": (
        "The transfer path reverts only when the recipient or sender equals a settable "
        "address (the DEX pair): buys succeed, sells fail."
    ),
    "EXIT_CALLBACK_CYCLE": (
        "The transfer path calls out to a settable address and then compares an "
        "amount-dependent value with privileged state, so sells can be made to revert "
        "without listing the seller."
    ),
    "FEE_UNBOUNDED": (
        "A privileged-writable number feeds the transferred or fee amount with no cap: the "
        "role can set the fee to 100 percent."
    ),
    "BAL_PRIV_MINT": (
        "A privileged function increases a balance or totalSupply outside the constructor: "
        "the role can print tokens."
    ),
    "BAL_PRIV_BURN_OTHER": (
        "A privileged function decreases the balance of an account other than the caller."
    ),
    "BAL_DIRECT_SET": "A privileged function assigns an arbitrary value to a balance entry.",
    "BAL_TRANSFER_HIDDEN_MINT": (
        "On the transfer path more is credited than debited, typically to a recipient other "
        "than the stated one."
    ),
    "VIEW_CALLER_DEPENDENT": (
        "balanceOf or totalSupply returns a value that depends on who is asking, so "
        "explorers and wallets are shown a different state than the one that settles."
    ),
    "FEE_ADDR_MUTABLE": (
        "The recipient of a fee or tax credited on the transfer path is a privileged-writable "
        "address."
    ),
    "LEAK_ARBITRARY_TRANSFERFROM": (
        "A privileged path debits an arbitrary account without reading its allowance."
    ),
    "LEAK_EXEMPT_PATH": (
        "A branch on the transfer path taken for a privileged sender credits the recipient "
        "while skipping the sender debit."
    ),
    "LEAK_PRIV_SWEEP": (
        "A privileged function sends the contract's whole ETH balance or its own tokens out; "
        "rescue of foreign tokens only is downgraded to informational."
    ),
    "SLITHER_HIGH_OVERLAY": (
        "One of Slither's built-in High-impact detectors fired; exploit-shape checks count "
        "as HIGH, all others are evidence only."
    ),
    "OWN_HIDDEN_ROLE": (
        "An address or map that gates privileged functions is not readable through any public "
        "variable or view: a second owner that explorers cannot show."
    ),
    "OWN_FAKE_RENOUNCE": (
        "A function clears one authority variable while another authority that still gates "
        "privileged functions survives, or the renounce writes a new non-zero authority."
    ),
    "OWN_REASSIGN_NONSTD": (
        "An authority variable is written outside the constructor by a function that is not "
        "gated by that authority, or set to a literal address or msg.sender."
    ),
    "OWN_TX_ORIGIN": "Authorisation compares tx.origin instead of msg.sender.",
    "STRUCT_EXTERNAL_GATE": (
        "The transfer path calls a contract at a privileged-writable address, so its behaviour "
        "cannot be determined from this source alone."
    ),
    "STRUCT_DELEGATECALL_SETTABLE": (
        "A delegatecall targets a privileged-writable address outside the standard proxy "
        "fallback shape: the role can replace the contract's code."
    ),
    "STRUCT_SELFDESTRUCT": "selfdestruct is reachable from a public or external function.",
    "STRUCT_PROXY_EOA_ADMIN": (
        "A proxy fallback delegates to an implementation address whose writer is gated by a "
        "single stored address."
    ),
    "DRAIN_APPROVAL_PULL": (
        "A non-privileged function pulls tokens from the caller via transferFrom or permit to "
        "an address that is not the caller, with nothing credited back."
    ),
    "HONEYPOT_LEGACY": (
        "A deposit is accepted but the ETH exit depends on a constructor-set or "
        "privileged-set secret, or on a balance comparison that cannot hold."
    ),
    "PONZI_SHAPE": (
        "ETH is paid to addresses stored by earlier payable calls and the contract has no "
        "value source other than msg.value."
    ),
}

# Discriminator names recorded on a finding (spec §"Discriminator classes") and what they mean
# to a reader; rendered next to a finding whose severity differs from its base severity.
DISCRIMINATOR_TITLES: dict[str, str] = {
    "managed_role": "role is granted only by a different role",
    "library_role": "authority comes from a vendored library",
    "issuer_token": "issuer-token shape (mint and burn both emit events)",
    "ungate_exists": "a privileged un-gate exists",
    "constant_floor": "every writer keeps the limit above a constant floor",
    "bounded_window": "gate only applies inside a constant time window",
    "constant_cap": "supply is capped by a constant",
    "role_separated_cap": "cap is set by a different role",
    "fee_cap": "fee is capped",
    "foreign_only": "only foreign tokens can be swept",
    "no_custody": "contract holds no user ETH",
    "no_expiry": "no writer bounds the gate in time",
    "representation_switch": "balance re-denomination",
    "one_shot_initializer": "one-shot initializer",
    "two_step_handoff": "two-step ownership handoff",
    "eq_self": "self-call authorisation",
    "priv_bypass": "privileged sender is exempt from the gate",
    "evidence_only": "evidence only",
}

# Fixed reason codes emitted by policy.py / engine.py and their judge-facing sentence.
REASON_SENTENCES: dict[str, str] = {
    "external_dependency": "transfer behaviour depends on a contract at a settable address",
    "compile_failed": "source did not compile with any pinned solc — not analysed",
    "timeout": "analysis exceeded the per-file time limit — not analysed",
    "analysis_error": "analysis raised an internal error — not analysed",
    "budget_exhausted": "global time budget exhausted before this file was analysed",
}

GOVERNANCE_NOTE: dict[str, str] = {
    "managed_role": "the power sits under a role-administered account (governance, not a code bound)",
    "issuer_token": "issuer-controlled token; centralization, not a bound",
    "role_separated_cap": "the cap is settable by another role, so it is not code-enforced",
}

BOUNDING_NOTE: dict[str, str] = {
    "constant_cap": "cap is a constant/immutable",
    "fee_cap": "fee is capped by a constant ratio in code",
    "constant_floor": "every writer keeps the limit above a constant floor",
    "bounded_window": "gate only applies inside a constant time window",
    "ungate_exists": "restriction is symmetric — an un-gate exists and the privileged path is not exempt",
    "no_custody": "contract holds no user ETH",
    "foreign_only": "only foreign tokens can be swept",
    "two_step_handoff": "two-step ownership handoff",
    "one_shot_initializer": "one-shot initializer",
    "representation_switch": "balance re-denomination",
}

BENIGN_NO_FINDINGS = "no privileged control over user funds found"
BENIGN_INFO_ONLY = "only informational role evidence"
UNCERTAIN_NO_REASON = "manual review required"


def rule_title(rule_id: str) -> str:
    return RULE_TITLES.get(rule_id, rule_id)


def rule_explanation(rule_id: str) -> str:
    return RULE_EXPLANATIONS.get(rule_id, "")


def family_title(family: str) -> str:
    return FAMILY_TITLES.get(family, family)


def discriminator_title(name: str) -> str:
    return DISCRIMINATOR_TITLES.get(name, name)


def governance_notes(finding: Finding) -> list[str]:
    return [GOVERNANCE_NOTE[name] for name in finding.discriminators if name in GOVERNANCE_NOTE]


def bounding_notes(finding: Finding) -> list[str]:
    return [BOUNDING_NOTE[name] for name in finding.discriminators if name in BOUNDING_NOTE]
