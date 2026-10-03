## Scoring rubric ##

#### **Principle**: the score is risk points (higher is worse), added up from a small set of signals. Every signal produces an auditable Factor, and nothing here uses the LLM. ####

|Signal	|Source	|Points|
|--|--|--|
|Unpatched vulnerabilities in the latest release	|OSV, after unique_issues	|worst issue: **CRITICAL 60, HIGH 50, MODERATE 25, LOW 10, unknown 25;** plus 3 per extra issue, extras capped at +10|
|Latest release yanked	|PyPI|	**+30**|
|Repository archived	|GitHub	|**+35**|
|Age of latest release	|PyPI|	over 3 years **+25**; over 18 months **+15**; over 12 months **+8**|
|Last push to the repo	|GitHub|	over 2 years **+15**; over 1 year **+8**|

 - **Score**: the sum, capped at 100.
 - **Rating bands**: LOW 0 to 24, MEDIUM 25 to 49, HIGH 50 or more. One unpatched HIGH or CRITICAL issue is a HIGH rating by itself.
 - **Why every returned OSV issue counts as unpatched**: we query the latest version, so any issue OSV returns is one that affects the current release.
 - **Unknown severity counts as MODERATE (25), never zero**. That's the rule I flagged earlier.
 - **Stars and open issues are not scored**. They're noisy and easy to game, and they go in the report as context only. Cutting them is a deliberate decision you can defend.

#### Confidence and the data-gap guardrail ####

|Situation	|Confidence	|Effect on rating|
|--|--|--|
|No gaps|	HIGH	|none|
|Only the GitHub source missing (including "no GitHub link found")	|MEDIUM	|rating cannot be LOW, so score floor 25|
|OSV or PyPI missing	|LOW|	rating cannot be LOW, so score floor 25|

#### Trade-offs to be ready to defend ####

 - A package hosted on GitLab can never be rated LOW. That's deliberate: absence of evidence is not evidence of safety. It goes in the README under limitations.
 - Old but stable libraries can look riskier than they are. The age points are modest (up to 25 and 15) so staleness alone gives MEDIUM, not HIGH.
 - If latest_release_at is missing it adds a factor with 0 points and the detail "unknown". It's a missing field, not a failed source.