"""
SentinelX — WAF Rule Engine
YAML-based rule evaluation engine similar to Sigma.
Loads rules from YAML files and evaluates incoming requests against them.
"""

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class RuleMatch:
    """Result of a rule match evaluation."""
    matched: bool
    rule_id: str
    rule_name: str
    category: str
    severity: str
    action: str
    matched_pattern: str = ""
    matched_value: str = ""
    matched_target: str = ""


@dataclass
class WAFRuleDefinition:
    """Parsed WAF rule definition."""
    id: str
    name: str
    description: str
    category: str
    severity: str
    action: str
    priority: int
    match_type: str  # "regex" | "exact" | "contains"
    targets: list[str]  # ["query_params", "body", "path", "headers"]
    patterns: list[str]
    compiled_patterns: list[re.Pattern] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Pre-compile regex patterns for performance."""
        if self.match_type == "regex":
            self.compiled_patterns = []
            for pattern in self.patterns:
                try:
                    self.compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
                except re.error as e:
                    logger.error(f"Invalid regex in rule {self.id}: {pattern} — {e}")


class RuleEngine:
    """
    WAF Rule evaluation engine.
    Loads rules from YAML files and evaluates requests against them.
    Rules are sorted by priority (lower = higher priority).
    """

    def __init__(self):
        self._rules: list[WAFRuleDefinition] = []
        self._rules_by_category: dict[str, list[WAFRuleDefinition]] = {}
        self._loaded = False

    @property
    def rules(self) -> list[WAFRuleDefinition]:
        return self._rules

    def get_all_rules(self) -> list[WAFRuleDefinition]:
        """Return all loaded WAF rule definitions."""
        return self._rules

    def load_rules_from_directory(self, rules_dir: str | Path | None = None) -> int:
        """Load all YAML rule files from the specified directory."""
        if rules_dir is None:
            rules_dir = Path(__file__).parent / "rules"
        else:
            rules_dir = Path(rules_dir)

        if not rules_dir.exists():
            logger.warning(f"Rules directory not found: {rules_dir}")
            return 0

        count = 0
        for yaml_file in sorted(rules_dir.glob("*.yaml")):
            count += self._load_rules_from_file(yaml_file)
        for yaml_file in sorted(rules_dir.glob("*.yml")):
            count += self._load_rules_from_file(yaml_file)

        # Sort by priority (lower number = higher priority)
        self._rules.sort(key=lambda r: r.priority)

        # Index by category
        self._rules_by_category.clear()
        for rule in self._rules:
            if rule.category not in self._rules_by_category:
                self._rules_by_category[rule.category] = []
            self._rules_by_category[rule.category].append(rule)

        self._loaded = True
        logger.info(f"Loaded {count} WAF rules from {rules_dir}")
        return count

    def _load_rules_from_file(self, filepath: Path) -> int:
        """Load rules from a single YAML file."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "rules" not in data:
                logger.warning(f"No rules found in {filepath}")
                return 0

            count = 0
            for rule_data in data["rules"]:
                try:
                    conditions = rule_data.get("conditions", {})
                    rule = WAFRuleDefinition(
                        id=rule_data["id"],
                        name=rule_data["name"],
                        description=rule_data.get("description", ""),
                        category=rule_data["category"],
                        severity=rule_data.get("severity", "medium"),
                        action=rule_data.get("action", "log"),
                        priority=rule_data.get("priority", 50),
                        match_type=conditions.get("match_type", "regex"),
                        targets=conditions.get("targets", ["query_params", "body"]),
                        patterns=conditions.get("patterns", []),
                        metadata=rule_data.get("metadata", {}),
                    )
                    self._rules.append(rule)
                    count += 1
                except KeyError as e:
                    logger.error(f"Missing required field in rule from {filepath}: {e}")
                except Exception as e:
                    logger.error(f"Error parsing rule from {filepath}: {e}")

            return count
        except Exception as e:
            logger.error(f"Failed to load rules from {filepath}: {e}")
            return 0

    def evaluate(self, request_data: dict[str, str]) -> RuleMatch | None:
        """
        Evaluate a request against all loaded rules.

        Args:
            request_data: Dict with keys matching rule targets:
                - "path": Request path
                - "query_params": Raw query string
                - "body": Request body as string
                - "headers": Concatenated header values
                - "user_agent": User agent string

        Returns:
            RuleMatch if a rule was triggered, None if clean.
        """
        if not self._loaded:
            self.load_rules_from_directory()

        for rule in self._rules:
            match = self._evaluate_rule(rule, request_data)
            if match and match.matched:
                return match

        return None

    def _evaluate_rule(
        self, rule: WAFRuleDefinition, request_data: dict[str, str]
    ) -> RuleMatch | None:
        """Evaluate a single rule against the request data."""
        for target in rule.targets:
            value = request_data.get(target, "")
            if not value:
                continue

            if rule.match_type == "regex":
                for i, compiled in enumerate(rule.compiled_patterns):
                    match = compiled.search(value)
                    if match:
                        return RuleMatch(
                            matched=True,
                            rule_id=rule.id,
                            rule_name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            action=rule.action,
                            matched_pattern=rule.patterns[i],
                            matched_value=match.group(0)[:200],
                            matched_target=target,
                        )
            elif rule.match_type == "exact":
                for pattern in rule.patterns:
                    if pattern.lower() == value.lower():
                        return RuleMatch(
                            matched=True,
                            rule_id=rule.id,
                            rule_name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            action=rule.action,
                            matched_pattern=pattern,
                            matched_value=value[:200],
                            matched_target=target,
                        )
            elif rule.match_type == "contains":
                for pattern in rule.patterns:
                    if pattern.lower() in value.lower():
                        return RuleMatch(
                            matched=True,
                            rule_id=rule.id,
                            rule_name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            action=rule.action,
                            matched_pattern=pattern,
                            matched_value=value[:200],
                            matched_target=target,
                        )

        return None

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def categories(self) -> list[str]:
        return list(self._rules_by_category.keys())

    def get_rules_by_category(self, category: str) -> list[WAFRuleDefinition]:
        return self._rules_by_category.get(category, [])


# Singleton engine instance
_engine_instance: RuleEngine | None = None


def get_rule_engine() -> RuleEngine:
    """Get or create the singleton rule engine instance."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = RuleEngine()
        _engine_instance.load_rules_from_directory()
    return _engine_instance
