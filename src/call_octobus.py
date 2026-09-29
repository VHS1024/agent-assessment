import json
import os
import urllib.request

def add_via_octobus(left, right):
    base = os.environ["OCTOBUS_BASE_URL"].rstrip("/")
    token = os.environ["OCTOBUS_TOKEN"]
    url = base + "/capsets/dev/connect/calculator-test/calculator.v1.CalculatorService/Add"
    body = json.dumps({"left": left, "right": right}).encode()
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
            "x-octobus-ext-business-request-id": "agent-demo-001",
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.loads(response.read().decode())
    print(json.dumps({"ok": True, "result": result}, ensure_ascii=False))

if __name__ == "__main__":
    add_via_octobus(20, 22)
