import secrets

from flask import Flask
from flask_cors import CORS

from .config import Config
from .extensions import db, jwt, limiter
from .ml.predictor import Predictor
from .routes import _error, api, register_error_handlers


def create_app(config_object=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)

    if not app.config["JWT_SECRET_KEY"]:
        if app.config["APP_ENV"] == "production":
            raise RuntimeError("JWT_SECRET_KEY must be set in production.")
        # Development only: tokens stop working when the server restarts.
        app.config["JWT_SECRET_KEY"] = secrets.token_hex(32)

    db.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}})

    app.extensions["predictor"] = Predictor(app.config["MODEL_DIR"])
    app.register_blueprint(api)
    register_error_handlers(app)
    _register_jwt_handlers()

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Cache-Control"] = "no-store"
        if app.config["APP_ENV"] == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    with app.app_context():
        db.create_all()  # Use Alembic/Flask-Migrate once the schema starts changing.

    return app


def _register_jwt_handlers() -> None:
    @jwt.unauthorized_loader
    def missing_token(reason):
        return _error("unauthorized", "Sign in to continue.", 401)

    @jwt.invalid_token_loader
    def invalid_token(reason):
        return _error("unauthorized", "Your session is not valid. Sign in again.", 401)

    @jwt.expired_token_loader
    def expired_token(header, payload):
        return _error("token_expired", "Your session has expired. Sign in again.", 401)
