import os
import httpx
from dotenv import load_dotenv

load_dotenv()

URL = "https://generativelanguage.googleapis.com/v1beta/models"
headers = {"x-goog-api-key": os.environ["LLM_API_KEY"]}
names, token = [], None

while True:
    params = {"pageSize": 1000}
    if token:
        params["pageToken"] = token
    r = httpx.get(URL, params=params, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()
    for m in data.get("models", []):
        if "generateContent" in m.get("supportedGenerationMethods", []):
            names.append(m["name"].replace("models/", ""))
    token = data.get("nextPageToken")
    if not token:
        break

SKIP = ["audio", "live", "tts", "image", "embedding", "imagen", "veo",
        "aqa", "robotics", "computer-use", "native", "lyria", "translate"]

for n in sorted(names):
    if not any(w in n.lower() for w in SKIP):
        print(n)