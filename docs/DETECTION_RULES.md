# Detection rules

SentinelScan reads Python syntax without running the code. It checks string
literals in simple, annotated, and chained assignments, attribute assignments
such as `self.password = "..."`, and assignments to string keys such as
`config["password"] = "..."`. It also checks string key/value pairs in
dictionary literals assigned to variables and string values passed as keyword
arguments.

| Rule ID | Severity | What matches |
| --- | --- | --- |
| `AWS_ACCESS_KEY` | HIGH | A value consisting of `AKIA` followed by 16 uppercase letters or digits. |
| `PASSWORD` | HIGH | A name containing `password`, `pwd`, or `passwd`. |
| `API_KEY` | HIGH | A name containing `api_key` or `apikey`. |
| `TOKEN` | MEDIUM | A name containing `token`. |
| `SECRET` | MEDIUM | A name containing `secret`. |

Name matches are case-insensitive and require a value at least four characters
long. A string can trigger more than one rule. Names such as `password_not_set`
can suppress name-based matches. Names such as `test_password` can lower
confidence. The AWS value pattern is evaluated regardless of name.

Severity describes the expected impact if the finding is real. Confidence
estimates how likely it is to be a real secret using signals such as length,
entropy, placeholder values, and name context. Review findings in context.
