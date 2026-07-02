"""Evaluate DetectionSignatures against transcript event streams (the labeled-replay engine).

A :class:`~finagent_redrange.types.DetectionSignature` is an oracle-faithful description of what a
landed attack looks like in an agent transcript. This module flattens a transcript into the flat
event stream a SIEM would log, decides whether a signature fires over it, and computes the
labeled-replay confusion matrix over the range's own controls-off (exploited) / controls-on
(blocked) transcript pairs.

The same evaluation is what the exported Sigma rules encode, so the two are kept provably
equivalent by the oracle-equivalence assertion in ``tests/test_export_sigma.py`` — an exported
detection can never silently drift from the oracle it came from.

Precision note: the corpus is the range's own 8x2 labeled transcripts (no benign/normal traffic),
so a rule's measured precision is *oracle/translation fidelity over labeled evidence*, NOT a
real-world false-positive rate. Tune before production use.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from finagent_redrange.types import DetectionSignature, FieldMatch

if TYPE_CHECKING:
    from finagent_redrange.types import Finding, Transcript

Event = dict[str, Any]


def events_from_transcript(transcript: Transcript) -> list[Event]:
    """Flatten a transcript into detection events (one per turn) — the shape a SIEM would log."""
    return [
        {
            "role": t.role.value,
            "content": t.content,
            "tool_name": t.tool_name,
            "tool_ok": t.tool_ok,
            "tool_args": t.tool_args or {},
        }
        for t in transcript.turns
    ]


def _resolve(event: Event, field: str) -> Any:
    """Resolve an event key or a dotted path into tool_args (e.g. ``tool_args.to_acct``)."""
    if "." in field:
        top, _, sub = field.partition(".")
        base = event.get(top)
        return base.get(sub) if isinstance(base, dict) else None
    return event.get(field)


def _match(fm: FieldMatch, event: Event) -> bool:
    actual = _resolve(event, fm.field)
    if fm.op == "eq":
        return actual == fm.value
    if fm.op == "contains":
        return actual is not None and str(fm.value) in str(actual)
    raise ValueError(f"unknown FieldMatch op: {fm.op!r}")


def _selection_matches(sig: DetectionSignature, event: Event) -> bool:
    return all(_match(fm, event) for fm in sig.selection)


def evaluate(sig: DetectionSignature, events: list[Event]) -> bool:
    """Whether the signature fires over an event stream.

    Fires if ANY event matches the ANDed selection — or, when ``count_over_threshold`` is set,
    only if MORE THAN that many events match (the unbounded-consumption count rule).
    """
    hits = sum(1 for e in events if _selection_matches(sig, e))
    if sig.count_over_threshold is not None:
        return hits > sig.count_over_threshold
    return hits > 0


# --- labeled-replay confusion matrix ------------------------------------------------------


@dataclass(frozen=True)
class RuleScore:
    """Per-rule confusion matrix over the whole labeled corpus.

    A rule is the detector for its own scenario; its single ground-truth positive is that
    scenario's controls-off (exploited) transcript. Every other transcript — its own controls-on
    (blocked) transcript and all other scenarios' transcripts — is a ground-truth negative.
    """

    scenario_id: str
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return round(self.tp / denom, 2) if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return round(self.tp / denom, 2) if denom else 0.0


def confusion_matrix(findings_off: list[Finding], findings_on: list[Finding]) -> list[RuleScore]:
    """Replay every scenario's signature over every transcript in the corpus and score each rule.

    ``findings_off`` carry the detection signatures (via ``Finding.detection``) and the exploited
    transcripts; ``findings_on`` carry the blocked transcripts. A rule that fires on any blocked
    or foreign transcript is a false positive; one that misses its own exploit is a false negative.
    """
    corpus: list[tuple[str, str, list[Event]]] = [
        (f.scenario_id, "off", events_from_transcript(f.transcript)) for f in findings_off
    ] + [(f.scenario_id, "on", events_from_transcript(f.transcript)) for f in findings_on]

    scores: list[RuleScore] = []
    for f in findings_off:
        sig = f.detection
        tp = fp = fn = tn = 0
        for owner, label, events in corpus:
            fired = evaluate(sig, events) if sig is not None else False
            is_positive = owner == f.scenario_id and label == "off"
            if is_positive and fired:
                tp += 1
            elif is_positive and not fired:
                fn += 1
            elif not is_positive and fired:
                fp += 1
            else:
                tn += 1
        scores.append(RuleScore(f.scenario_id, tp, fp, fn, tn))
    return scores
