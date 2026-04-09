from flask import Flask, render_template, jsonify
from server.routes import api
from server.logger_config import configure_logging
from server.crypto_utils import ensure_server_keys, get_server_public_key_fingerprint

def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder="client/templates",
        static_folder="client/static",
        static_url_path="/static",
    )

    configure_logging()
    ensure_server_keys()
    app.register_blueprint(api)

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            server_fingerprint=get_server_public_key_fingerprint(),
        )

    @app.get("/health")
    def health():
        return jsonify(
            {
                "app": "SecureChat",
                "status": "running",
                "message": "Browser UI available at /",
            }
        )

    return app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
