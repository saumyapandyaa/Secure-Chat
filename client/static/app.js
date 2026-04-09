class SecureChatWebClient {
    constructor() {
        this.sessionId = null;
        this.serverId = null;
        this.clientSeq = 0;
        this.serverSeq = 0;
        this.clientToServerKey = null;
        this.serverToClientKey = null;
    }

    async startHandshake(expectedFingerprint) {
        this.log("Starting secure handshake...");

        const startResp = await fetch("/api/handshake/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                client_id: "browser-client",
                supported_kdf: "HKDF-SHA256",
                supported_cipher: "AES-256-GCM"
            })
        });

        const serverHello = await startResp.json();
        if (!startResp.ok) throw new Error(serverHello.message || "Handshake start failed");

        const actualFingerprint = await this.fingerprintPem(serverHello.server_public_key_pem);
        if (actualFingerprint !== expectedFingerprint.trim()) {
            throw new Error(`Server fingerprint mismatch.\nExpected: ${expectedFingerprint}\nActual:   ${actualFingerprint}`);
        }

        this.serverId = serverHello.server_id;
        updateValue("serverId", this.serverId);
        updateValue("fingerprintStatus", "Verified", "success");
        this.log("Server fingerprint verified.");

        const publicKey = await this.importRsaPublicKey(serverHello.server_public_key_pem);
        const serverNonce = b64ToBytes(serverHello.server_nonce);
        const clientNonce = crypto.getRandomValues(new Uint8Array(16));
        const premasterSecret = crypto.getRandomValues(new Uint8Array(32));

        const encryptedPremaster = await crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            premasterSecret
        );

        const completeResp = await fetch("/api/handshake/complete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_init_id: serverHello.session_init_id,
                client_id: "browser-client",
                client_nonce: bytesToB64(clientNonce),
                encrypted_premaster_secret: bytesToB64(new Uint8Array(encryptedPremaster))
            })
        });

        const completeBody = await completeResp.json();
        if (!completeResp.ok) throw new Error(completeBody.message || "Handshake completion failed");

        const derived = await this.deriveSessionKeys(premasterSecret, clientNonce, serverNonce);
        this.clientToServerKey = derived.clientToServerKey;
        this.serverToClientKey = derived.serverToClientKey;
        this.sessionId = completeBody.session_id;
        this.clientSeq = 0;
        this.serverSeq = 0;

        updateValue("sessionId", this.sessionId);
        updateValue("statusText", "Connected", "success");
        setConnectedUi(true);

        this.log(`Handshake complete. Session established: ${this.sessionId}`);
    }

    async sendMessage(message) {
        if (!this.sessionId) throw new Error("No active session");

        const record = await this.encryptRecord(message);
        const resp = await fetch("/api/message/send", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(record)
        });

        const body = await resp.json();
        if (!resp.ok) throw new Error(body.message || "Message send failed");

        const reply = await this.decryptReply(body.reply_record);
        this.log(`Secure message sent. Server reply decrypted: ${reply.message}`);
        document.getElementById("responseBox").value = JSON.stringify(reply, null, 2);
        return body;
    }

    async tamperTest(message) {
        if (!this.sessionId) throw new Error("No active session");

        const record = await this.encryptRecord(message);
        const bytes = b64ToBytes(record.ciphertext);
        bytes[0] ^= 0x01;
        record.ciphertext = bytesToB64(bytes);

        const resp = await fetch("/api/message/send", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(record)
        });

        const body = await resp.json();
        document.getElementById("testResult").value = JSON.stringify(body, null, 2);
        this.log(`Tamper test result: ${body.message || body.status}`);
        return body;
    }

    async replayTest(message) {
        if (!this.sessionId) throw new Error("No active session");

        const record = await this.encryptRecord(message);

        const firstResp = await fetch("/api/message/send", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(record)
        });
        const firstBody = await firstResp.json();

        const replayResp = await fetch("/api/message/send", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(record)
        });
        const replayBody = await replayResp.json();

        const result = {
            first_send_status: firstResp.status,
            first_send_body: firstBody,
            replay_send_status: replayResp.status,
            replay_send_body: replayBody
        };

        document.getElementById("testResult").value = JSON.stringify(result, null, 2);
        this.log(`Replay test result: ${replayBody.message || replayBody.status}`);
        return result;
    }

    async wrongFingerprintTest() {
        try {
            await this.startHandshake("deadbeef".repeat(8));
        } catch (err) {
            document.getElementById("testResult").value = String(err.message);
            this.log(`Wrong fingerprint test blocked connection: ${err.message}`);
            updateValue("fingerprintStatus", "Rejected", "fail");
            updateValue("statusText", "Disconnected", "neutral");
            setConnectedUi(false);
            this.sessionId = null;
            return;
        }
        throw new Error("Wrong fingerprint test unexpectedly succeeded");
    }

    async closeSession() {
        if (!this.sessionId) return;

        await fetch("/api/session/close", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: this.sessionId })
        });

        this.log(`Session closed: ${this.sessionId}`);
        this.sessionId = null;
        this.clientSeq = 0;
        this.serverSeq = 0;
        this.clientToServerKey = null;
        this.serverToClientKey = null;
        updateValue("statusText", "Disconnected", "neutral");
        updateValue("sessionId", "-");
        setConnectedUi(false);
    }

    async encryptRecord(message) {
        this.clientSeq += 1;
        const seq = this.clientSeq;
        const nonce = crypto.getRandomValues(new Uint8Array(12));
        const aad = encoder.encode(`${this.sessionId}:${seq}`);
        const plaintext = encoder.encode(JSON.stringify({
            type: "chat",
            sender: "browser-client",
            message,
            timestamp: Math.floor(Date.now() / 1000)
        }));

        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: nonce, additionalData: aad },
            this.clientToServerKey,
            plaintext
        );

        return {
            session_id: this.sessionId,
            seq,
            nonce: bytesToB64(nonce),
            ciphertext: bytesToB64(new Uint8Array(ciphertext))
        };
    }

    async decryptReply(record) {
        const seq = Number(record.seq);
        if (seq <= this.serverSeq) throw new Error("Replay detected in server reply");

        const nonce = b64ToBytes(record.nonce);
        const ciphertext = b64ToBytes(record.ciphertext);
        const aad = encoder.encode(`${this.sessionId}:${seq}`);

        const plaintextBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: nonce, additionalData: aad },
            this.serverToClientKey,
            ciphertext
        );

        this.serverSeq = seq;
        return JSON.parse(decoder.decode(plaintextBuffer));
    }

    async importRsaPublicKey(pem) {
        return crypto.subtle.importKey(
            "spki",
            pemToArrayBuffer(pem),
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["encrypt"]
        );
    }

    async fingerprintPem(pem) {
        const data = encoder.encode(pem);
        const hash = await crypto.subtle.digest("SHA-256", data);
        return bytesToHex(new Uint8Array(hash));
    }

    async deriveSessionKeys(premasterSecret, clientNonce, serverNonce) {
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            premasterSecret,
            "HKDF",
            false,
            ["deriveBits"]
        );

        const salt = concatBytes(clientNonce, serverNonce);
        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt,
                info: encoder.encode("SecureChat v1 session")
            },
            keyMaterial,
            512
        );

        const derivedBytes = new Uint8Array(derivedBits);
        const c2s = derivedBytes.slice(0, 32);
        const s2c = derivedBytes.slice(32, 64);

        const clientToServerKey = await crypto.subtle.importKey(
            "raw",
            c2s,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );

        const serverToClientKey = await crypto.subtle.importKey(
            "raw",
            s2c,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
        );

        return { clientToServerKey, serverToClientKey };
    }

    log(message) {
        const box = document.getElementById("logBox");
        const timestamp = new Date().toLocaleTimeString();
        box.value += `[${timestamp}] ${message}\n`;
        box.scrollTop = box.scrollHeight;
    }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const client = new SecureChatWebClient();

function updateValue(id, text, cls = null) {
    const el = document.getElementById(id);
    el.textContent = text;
    if (cls) el.className = `value ${cls}`;
}

function setConnectedUi(connected) {
    document.getElementById("sendBtn").disabled = !connected;
    document.getElementById("tamperBtn").disabled = !connected;
    document.getElementById("replayBtn").disabled = !connected;
    document.getElementById("closeBtn").disabled = !connected;
}

function bytesToB64(bytes) {
    let binary = "";
    bytes.forEach((b) => { binary += String.fromCharCode(b); });
    return btoa(binary);
}

function b64ToBytes(base64) {
    const binary = atob(base64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function pemToArrayBuffer(pem) {
    const b64 = pem.replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace(/\s+/g, "");
    return b64ToBytes(b64).buffer;
}

function concatBytes(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
}

document.getElementById("copyFingerprintBtn").addEventListener("click", () => {
    document.getElementById("expectedFingerprint").value =
        document.getElementById("currentServerFingerprint").textContent.trim();
});

document.getElementById("startBtn").addEventListener("click", async () => {
    try {
        const expectedFingerprint = document.getElementById("expectedFingerprint").value.trim();
        if (!expectedFingerprint) throw new Error("Paste or copy a pinned fingerprint first.");
        await client.startHandshake(expectedFingerprint);
    } catch (err) {
        client.log(`Handshake failed: ${err.message}`);
        updateValue("statusText", "Disconnected", "neutral");
        updateValue("fingerprintStatus", "Failed", "fail");
        document.getElementById("testResult").value = String(err.message);
    }
});

document.getElementById("sendBtn").addEventListener("click", async () => {
    try {
        const message = document.getElementById("messageInput").value.trim();
        if (!message) throw new Error("Enter a message first.");
        const result = await client.sendMessage(message);
        document.getElementById("testResult").value = JSON.stringify(result, null, 2);
    } catch (err) {
        client.log(`Send failed: ${err.message}`);
        document.getElementById("testResult").value = String(err.message);
    }
});

document.getElementById("tamperBtn").addEventListener("click", async () => {
    try {
        await client.tamperTest("This message will be tampered with");
    } catch (err) {
        client.log(`Tamper test error: ${err.message}`);
        document.getElementById("testResult").value = String(err.message);
    }
});

document.getElementById("replayBtn").addEventListener("click", async () => {
    try {
        await client.replayTest("This message will be replayed");
    } catch (err) {
        client.log(`Replay test error: ${err.message}`);
        document.getElementById("testResult").value = String(err.message);
    }
});

document.getElementById("wrongKeyBtn").addEventListener("click", async () => {
    try {
        await client.wrongFingerprintTest();
    } catch (err) {
        client.log(`Wrong fingerprint test error: ${err.message}`);
        document.getElementById("testResult").value = String(err.message);
    }
});

document.getElementById("closeBtn").addEventListener("click", async () => {
    await client.closeSession();
});
