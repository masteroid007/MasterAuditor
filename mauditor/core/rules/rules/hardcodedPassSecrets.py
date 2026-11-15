from ..base import BaseRule, _is_string_literal, _keyword_arguments
from mauditor.core.models import DataAnalysis
from mauditor.core.models import Finding, Severity

def _hardcoded_findings(data_analysis: DataAnalysis, rule_id: str, description: str, severity: Severity, names: set[str]) -> list[Finding]:
    findings = []
    for variable in data_analysis.info_variables:
        name = str(variable.get("name", "")).lower()
        value = variable.get("value")
        if name in names and _is_string_literal(value):
            findings.append(Finding(rule_id, description, data_analysis.file_path, variable["line"], severity))

    for call in data_analysis.info_calls:
        for name, value in _keyword_arguments(call).items():
            if name.lower() in names and _is_string_literal(value):
                findings.append(Finding(rule_id, description, data_analysis.file_path, call["line"], severity))
    return findings


class HardcodedPasswordRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC011",
            description="Rilevata password hardcoded.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        return _hardcoded_findings(data_analysis, self.rule_id, self.description, self.severity, {"password", "passwd", "pwd"})

class HardcodedSecretRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC012",
            description="Rilevato secret hardcoded.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        return _hardcoded_findings(data_analysis, self.rule_id, self.description, self.severity, {"secret"})
    
class HardcodedTokenRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC013",
            description="Rilevato token hardcoded.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        return _hardcoded_findings(data_analysis, self.rule_id, self.description, self.severity, {"token"})

class HardcodedApiKeyRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC014",
            description="Rilevata API key hardcoded.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        return _hardcoded_findings(data_analysis, self.rule_id, self.description, self.severity, {"api_key", "apikey"})
    
class HardcodedSecretKeyRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC015",
            description="Rilevata secret key hardcoded.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        return _hardcoded_findings(data_analysis, self.rule_id, self.description, self.severity, {"secret_key", "secretkey"})

class HardcodedAccessTokenRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC016",
            description="Rilevato access token hardcoded.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        return _hardcoded_findings(data_analysis, self.rule_id, self.description, self.severity, {"access_token", "accesstoken"})

class HardcodedRefreshTokenRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC017",
            description="Rilevato refresh token hardcoded.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        return _hardcoded_findings(data_analysis, self.rule_id, self.description, self.severity, {"refresh_token", "refreshtoken"})

class HardcodedClientSecretRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC018",
            description="Rilevato client secret hardcoded.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        return _hardcoded_findings(data_analysis, self.rule_id, self.description, self.severity, {"client_secret", "clientsecret"})

class HardcodedPrivateKeyRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC019",
            description="Rilevato private key hardcoded.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        return _hardcoded_findings(data_analysis, self.rule_id, self.description, self.severity, {"private_key", "privatekey"})

class HardcodedDatabaseCredentialsRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC020",
            description="Rilevato database credentials hardcoded.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        return _hardcoded_findings(data_analysis, self.rule_id, self.description, self.severity, {"db_credentials", "dbcredentials", "database_credentials"})

class HardcodedConnectionStringRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC021",
            description="Rilevato connection string hardcoded.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        return _hardcoded_findings(data_analysis, self.rule_id, self.description, self.severity, {"connection_string", "connectionstring"})