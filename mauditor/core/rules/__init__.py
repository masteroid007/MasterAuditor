from .base import BaseRule, _call_name, _has_keyword_argument
from . import rules as _rules

_rule_names = sorted(
    name
    for name, value in vars(_rules).items()
    if (
        isinstance(value, type)
        and issubclass(value, BaseRule)
        and value is not BaseRule
        and value.__module__ == _rules.__name__
    )
)

globals().update({name: getattr(_rules, name) for name in _rule_names})

__all__ = [
    *_rule_names
]

del _rule_names, _rules