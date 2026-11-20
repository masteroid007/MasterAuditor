from mauditor.core.rules.base import BaseRule


class Registry:
    def __init__(self):
        self.rules: dict[str, type[BaseRule]] = {}

    def register(self, rule_id: str, rule: type[BaseRule]) -> None:
        if not isinstance(rule_id, str):
            raise TypeError("Rule ID must be a string.")

        rule_id = rule_id.strip()
        if not rule_id:
            raise ValueError("Rule ID cannot be empty.")

        if not isinstance(rule, type) or not issubclass(rule, BaseRule):
            raise TypeError("Rule must be a subclass of BaseRule.")

        if rule_id in self.rules:
            raise ValueError(f"Rule with ID '{rule_id}' is already registered.")

        instance = rule()
        if instance.rule_id != rule_id:
            raise ValueError(
                f"Rule ID mismatch: registry received '{rule_id}', "
                f"but the class declares '{instance.rule_id}'."
            )

        self.rules[rule_id] = rule

    def get_rule(self, rule_id: str) -> type[BaseRule] | None:
        if not isinstance(rule_id, str):
            raise TypeError("Rule ID must be a string.")
        return self.rules.get(rule_id.strip())

    def unregister(self, rule_id: str) -> bool:
        if not isinstance(rule_id, str):
            raise TypeError("Rule ID must be a string.")
        return self.rules.pop(rule_id.strip(), None) is not None

    def get_all_rules(self) -> dict[str, type[BaseRule]]:
        return self.rules.copy()

    @classmethod
    def default(cls) -> "Registry":
        from .rules import (
            EvalRule,
            ExecRule,
            CompileRule,
            OsSystemRule,
            CommandInjectionRule,
            SqlInjectionRule,
            DynamicImportRule,
            PickleRule,
            UnsafeYamlLoadRule,
            HardcodedPasswordRule,
            HardcodedSecretRule,
            HardcodedTokenRule,
            HardcodedApiKeyRule,
            HardcodedSecretKeyRule,
            HardcodedAccessTokenRule,
            HardcodedRefreshTokenRule,
            HardcodedClientSecretRule,
            HardcodedPrivateKeyRule,
            HardcodedDatabaseCredentialsRule,
            HardcodedConnectionStringRule,
            WeakHashAlgorithmRule,
            InsecureRandomRule,
            WeakPasswordHashRule,
            InsecureTLSRule,
            InsecureHTTPRule,
            SSRFRule,
            PathTraversalRule,
            InsecureTempFileRule,
        )

        rule_classes = (
            EvalRule,
            ExecRule,
            CompileRule,
            OsSystemRule,
            CommandInjectionRule,
            SqlInjectionRule,
            DynamicImportRule,
            PickleRule,
            UnsafeYamlLoadRule,
            HardcodedPasswordRule,
            HardcodedSecretRule,
            HardcodedTokenRule,
            HardcodedApiKeyRule,
            HardcodedSecretKeyRule,
            HardcodedAccessTokenRule,
            HardcodedRefreshTokenRule,
            HardcodedClientSecretRule,
            HardcodedPrivateKeyRule,
            HardcodedDatabaseCredentialsRule,
            HardcodedConnectionStringRule,
            WeakHashAlgorithmRule,
            InsecureRandomRule,
            WeakPasswordHashRule,
            InsecureTLSRule,
            InsecureHTTPRule,
            SSRFRule,
            PathTraversalRule,
            InsecureTempFileRule,
        )

        registry = cls()
        for rule_class in rule_classes:
            instance = rule_class()
            registry.register(instance.rule_id, rule_class)

        return registry
