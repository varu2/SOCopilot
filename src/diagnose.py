import os
import sys
import time
from dotenv import load_dotenv
from openai import OpenAI, APIStatusError

load_dotenv()

client = OpenAI(
    base_url=os.environ["LLM_BASE_URL"],
    api_key=os.environ["LLM_API_KEY"],
    max_retries=0,
    timeout=60,
)

models = sys.argv[1:] or [os.environ["LLM_MODEL"]]

for model in models:
    print("\nModel:", model)
    start = time.time()
    try:
        r = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Say hello in one line."}],
        )
        print("OK:", r.choices[0].message.content)
    except APIStatusError as e:
        print("Status:", e.status_code)
    print(f"{time.time() - start:.1f} seconds")