import os
import sys
from dotenv import load_dotenv
from openai import OpenAI, APIStatusError

load_dotenv()

client = OpenAI(
    base_url=os.environ["LLM_BASE_URL"],
    api_key=os.environ["LLM_API_KEY"],
    max_retries=5,
)

# Optional: pass a model name to test it without editing .env
model = sys.argv[1] if len(sys.argv) > 1 else os.environ["LLM_MODEL"]
print("Using model:", model)

try:
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": "Say hello in one line."}],
    )
    print(resp.choices[0].message.content)
except APIStatusError as e:
    print("Status:", e.status_code)
    print("Details:", e.response.text)