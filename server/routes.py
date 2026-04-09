import logging
from flask import Blueprint, jsonify, request

from server.handshake import start_handshake, complete_handshake
from server.record_layer import unprotect_incoming_message, protect_outgoing_message, ReplayError, IntegrityError
from server.session_manager import session_manager

logger = logging.getLogger(__name__)

api = Blueprint("api", __name__)

@api.post("/api/handshake/start")
def api_handshake_start():
    data = request.get_json(silent=True) or {}
    client_id = data.get("client_id", "client1")
    response = start_handshake(client_id=client_id)
    return jsonify(response), 200

@api.post("/api/handshake/complete")
def api_handshake_complete():
    data = request.get_json(force=True)
    try:
        response = complete_handshake(data)
        return jsonify(response), 200
    except Exception as exc:
        logger.exception("Handshake completion failed")
        return jsonify({"status": "error", "message": str(exc)}), 400

@api.post("/api/message/send")
def api_message_send():
    data = request.get_json(force=True)
    session_id = data.get("session_id")
    if not session_id:
        return jsonify({"status": "error", "message": "session_id is required"}), 400

    session = session_manager.get_active(session_id)
    if session is None or not session.active:
        return jsonify({"status": "error", "message": "Invalid or inactive session"}), 400

    try:
        plaintext_message = unprotect_incoming_message(session, data, direction="client_to_server")
        logger.info("Secure message received in session_id=%s: %s", session_id, plaintext_message)

        response_payload = {
            "type": "server_echo",
            "message": f"Server received: {plaintext_message.get('message', '')}",
            "timestamp": plaintext_message.get("timestamp"),
        }
        encrypted_reply = protect_outgoing_message(session, response_payload, direction="server_to_client")

        return jsonify({
            "status": "ok",
            "received_plaintext": plaintext_message,
            "reply_record": encrypted_reply,
        }), 200

    except ReplayError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except IntegrityError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        logger.exception("Unexpected message processing error")
        return jsonify({"status": "error", "message": str(exc)}), 500

@api.post("/api/session/close")
def api_session_close():
    data = request.get_json(force=True)
    session_id = data.get("session_id")
    if not session_id:
        return jsonify({"status": "error", "message": "session_id is required"}), 400

    closed = session_manager.close_session(session_id)
    if not closed:
        return jsonify({"status": "error", "message": "Unknown session"}), 400

    return jsonify({"status": "ok", "message": "Session closed"}), 200
