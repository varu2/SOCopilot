import json
import os
import re
import sys
import time

from dotenv import load_dotenv
from openai import OpenAI

from enrichment import load_alerts, load_lookups, enrich_alert

load_dotenv()

MODEL = os.environ.get("LLM_MODEL", "")
PROMPT_VERSION = "v2"

SYSTEM_PROMPT = """You are a Tier-1 SOC analyst assistant. You receive one authentication-related \
security alert plus context about the user, the destination asset and the source IP. \
Decide whether the alert is a genuine threat (true_positive) or benign activity (false_positive).

Definitions: true_positive means the activity is genuinely malicious, unauthorized or a policy \
violation that needs investigation or response. false_positive means the alert fired but the \
activity is benign (for example authorized activity, user error or a misconfiguration). \
Needing a fix or follow-up does not by itself make an alert a true_positive. \
Your verdict must agree with your reasoning: if you identify a benign explanation, the verdict \
is false_positive.

How to reason:
- Use only facts present in the input. Never invent details. If a context block says \
"No record", say that context is missing.
- Check the source IP reputation and category.
- Compare the activity with the user's role, normal country, working hours, travel, \
on-call duty and password history, where these are given.
- Consider asset criticality, whether it is internet-facing, and whether the user's \
department is allowed to use it.
- Compare the alert timestamp with any approved window or authorization noted in the context.
- Service accounts and built-in administrator accounts should not normally log in interactively.
- If the context documents a legitimate, authorized explanation, lean false_positive. \
If the IP is malicious or suspicious, or the activity does not fit the user's role, \
hours or location, lean true_positive.
- Severity reflects the impact if the alert is real (privileged accounts, high-value users \
and critical assets raise it). Use "low" for false positives.
- mitre_technique is the single best-fitting MITRE ATT&CK technique ID (for example \
T1110.001). Use "N/A" for false positives.

Respond with ONLY one JSON object, no markdown and no extra text, using exactly these keys:
{
  "verdict": "true_positive" or "false_positive",
  "confidence": integer from 0 to 100,
  "severity": "low", "medium", "high" or "critical",
  "mitre_technique": "T-number or N/A",
  "reasoning": "2-4 sentences citing the specific facts you used",
  "recommended_action": "one concrete next step for the analyst"
}"""

VALID_VERDICTS = {"true_positive", "false_positive"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
REQUIRED_KEYS = ["verdict", "confidence", "severity", "mitre_technique",
                 "reasoning", "recommended_action"]


def get_client():
    return OpenAI(
        base_url=os.environ["LLM_BASE_URL"],
        api_key=os.environ["LLM_API_KEY"],
        max_retries=5,
        timeout=60,
    )


def extract_json(text):
    """Pull the JSON object out of the model's reply, even if it adds fences or extra text."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("No JSON object found in reply")
    return json.loads(text[start:end + 1])


def validate(result):
    missing = [k for k in REQUIRED_KEYS if k not in result]
    if missing:
        raise ValueError(f"Missing fields: {missing}")
    if result["verdict"] not in VALID_VERDICTS:
        raise ValueError(f"Bad verdict: {result['verdict']}")
    if result["severity"] not in VALID_SEVERITIES:
        raise ValueError(f"Bad severity: {result['severity']}")
    return result


def triage_alert(enriched, attempts=2):
    """Send one enriched alert to the LLM and return a validated triage dict."""
    client = get_client()
    last_error = None
    for _ in range(attempts):
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(enriched, indent=2)},
            ],
        )
        raw = resp.choices[0].message.content or ""
        try:
            return validate(extract_json(raw))
        except ValueError as e:  # includes json.JSONDecodeError
            last_error = e
    raise RuntimeError(f"No valid JSON after {attempts} attempts: {last_error}")


if __name__ == "__main__":
    index = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    alerts = load_alerts()
    lookups = load_lookups()
    alert = alerts[index]
    print(f"Triaging {alert['alert_id']} ({alert['rule_name']}) | prompt {PROMPT_VERSION}\n")
    start = time.time()
    result = triage_alert(enrich_alert(alert, lookups))
    print(json.dumps(result, indent=2))
    print(f"\n(took {time.time() - start:.1f} seconds)")