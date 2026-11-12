"""GPU-free stand-in for vLLM's chat endpoint, for checking score_vllm.py's parsing. Standard library only.

    python3 stub_logprobs_server.py <port>

Answers every chat request with one token and top-20 logprobs. A request whose user message mentions
US133000000121212121212 (the attacker IBAN) gets " no" on top; every other one gets "Yes". The list mixes
case and spacing variants, so the scorer's matching is exercised too.
"""
import json
import math
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


def top_logprobs(attack):
    probs = ([(" no", 0.7), ("No", 0.1), ("yes", 0.15), (" Yes", 0.05)] if attack
             else [("Yes", 0.8), (" yes", 0.1), ("no", 0.08), (" No", 0.02)])
    filler = [(f"tok{i}", 1e-6) for i in range(16)]
    return [{"token": t, "logprob": math.log(p), "bytes": list(t.encode())} for t, p in probs + filler]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        text = " ".join(str(m.get("content")) for m in req.get("messages", []) if m.get("role") == "user")
        top = top_logprobs("US133000000121212121212" in text)
        body = json.dumps({
            "id": "stub", "object": "chat.completion", "created": 0, "model": req.get("model"),
            "choices": [{"index": 0, "finish_reason": "length",
                         "message": {"role": "assistant", "content": top[0]["token"]},
                         "logprobs": {"content": [{**top[0], "top_logprobs": top}]}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
