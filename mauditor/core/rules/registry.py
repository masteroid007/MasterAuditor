from mauditor.core.rules.base import BaseRule

class Registry:
    def __init__(self):
        self.rules = {}

    def register(self, rule_id: str, rule: type[BaseRule]) -> None:
        if not isinstance(rule_id, str):
            raise TypeError("Rule ID must be a string.")

        if not rule_id.strip():
            raise ValueError("Rule ID cannot be empty.")
        
        rule_id = rule_id.strip()

        if not isinstance(rule, type):
            raise TypeError("Rule must be a class.")

        if not issubclass(rule, BaseRule):
            raise TypeError("Rule must be a subclass of BaseRule.")

        if rule_id in self.rules:
            raise ValueError(f"Rule with ID '{rule_id}' is already registered.")

        self.rules[rule_id] = rule
        
    def get_rule(self, rule_id: str) -> type[BaseRule] | None:
        if not isinstance(rule_id, str):
            raise TypeError("Rule ID must be a string.")
        
        rule_id = rule_id.strip()
        return self.rules.get(rule_id)

    def unregister(self, rule_id: str):        
        if not isinstance(rule_id, str):
            raise TypeError("Rule ID must be a string.")
        
        rule_id = rule_id.strip()
        
        if rule_id in self.rules:
            del self.rules[rule_id]
            return True
        else:
            return False
    
    def get_all_rules(self) -> dict[str, type[BaseRule]]:
        return dict.copy(self.rules)
    

    @classmethod
    def default(cls) -> "Registry":
        from mauditor.core.rules.rules import (
            EvalRule,
            ExecRule,
            CompileRule,
            SubprocessShellRule,
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
        )

        registry = cls()

        rules = (
            EvalRule,
            ExecRule,
            CompileRule,
            SubprocessShellRule,
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
        )

        for rule_class in rules:
            rule = rule_class()
            registry.register(rule.rule_id, rule_class)

        return registry
