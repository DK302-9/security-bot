import os
from flask import Flask, request, jsonify, abort
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

app = Flask(__name__)

PUBLIC_KEY = os.environ.get("DISCORD_PUBLIC_KEY")

@app.route("/interactions", methods=["POST"])
def interactions():
    if not PUBLIC_KEY:
        return "DISCORD_PUBLIC_KEY is not configured", 500

    signature = request.headers.get("X-Signature-Ed25519")
    timestamp = request.headers.get("X-Signature-Timestamp")

    if not signature or not timestamp:
        abort(401)

    try:
        verify_key = VerifyKey(bytes.fromhex(PUBLIC_KEY))
        verify_key.verify(
            timestamp.encode() + request.data,
            bytes.fromhex(signature)
        )
    except (BadSignatureError, ValueError):
        abort(401)

    data = request.get_json()

    if data.get("type") == 1:
        return jsonify({"type": 1})

    if data.get("type") == 2:
        command_name = data.get("data", {}).get("name", "unknown")
        return jsonify({
            "type": 4,
            "data": {
                "content": f"🛡️ Security Bot received: /{command_name}"
            }
        })

    return jsonify({"type": 1})


@app.route("/")
def home():
    return "🛡️ Security Bot is online!"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)