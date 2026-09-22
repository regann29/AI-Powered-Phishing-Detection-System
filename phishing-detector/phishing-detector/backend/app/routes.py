from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, limiter
from .ml.predictor import ModelNotReady
from .models import Scan, User
from .privacy import email_preview, fingerprint, url_preview
from .validators import (
    ValidationError,
    json_body,
    positive_int,
    validate_credentials,
    validate_email_payload,
    validate_url_payload,
)

api = Blueprint("api", __name__, url_prefix="/api")

# Verified against when the account does not exist, so login timing does not reveal valid emails.
_DUMMY_HASH = generate_password_hash("not-a-real-password")


def predictor():
    return current_app.extensions["predictor"]


def current_user() -> User | None:
    user_id = get_jwt_identity()
    return db.session.get(User, int(user_id)) if user_id and str(user_id).isdigit() else None


def _owned_scan(scan_id: int) -> Scan | None:
    """A scan is only visible to the account that created it."""
    user = current_user()
    if not user:
        return None
    return db.session.scalar(db.select(Scan).where(Scan.id == scan_id, Scan.user_id == user.id))


def _error(code: str, message: str, status: int, field: str | None = None):
    body = {"error": {"code": code, "message": message}}
    if field:
        body["error"]["field"] = field
    return jsonify(body), status


@api.get("/health")
@limiter.exempt
def health():
    return jsonify(status="ok", models_ready=predictor().ready, model_version=predictor().version)


# ---------------------------------------------------------------- auth

@api.post("/auth/register")
@limiter.limit("5 per minute")
def register():
    email, password = validate_credentials(json_body(), check_strength=True)
    if User.query.filter_by(email=email).first():
        return _error("email_taken", "An account with this email already exists.", 409, "email")
    user = User(email=email, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    return jsonify(id=user.id, email=user.email), 201


@api.post("/auth/login")
@limiter.limit("10 per minute")
def login():
    email, password = validate_credentials(json_body())
    user = User.query.filter_by(email=email).first()
    valid = check_password_hash(user.password_hash if user else _DUMMY_HASH, password)
    if not user or not valid:
        return _error("invalid_credentials", "Email or password is incorrect.", 401)
    token = create_access_token(identity=str(user.id))
    return jsonify(access_token=token, user={"id": user.id, "email": user.email})


# ---------------------------------------------------------------- scanning

def _store(user: User, kind: str, preview: str, digest: str, result: dict) -> Scan:
    scan = Scan(
        user_id=user.id,
        kind=kind,
        input_preview=preview,
        input_hash=digest,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        verdict=result["verdict"],
        indicators=result["indicators"],
        details=result["details"],
        model_version=predictor().version,
    )
    db.session.add(scan)
    db.session.commit()
    return scan


@api.post("/scan/url")
@jwt_required()
@limiter.limit("30 per minute")
def scan_url():
    user = current_user()
    if not user:
        return _error("unauthorized", "Account no longer exists.", 401)
    url = validate_url_payload(json_body())
    result = predictor().predict_url(url)
    scan = _store(user, "url", url_preview(url), fingerprint(url), result)
    return jsonify(scan.to_dict()), 201


@api.post("/scan/email")
@jwt_required()
@limiter.limit("30 per minute")
def scan_email():
    user = current_user()
    if not user:
        return _error("unauthorized", "Account no longer exists.", 401)
    data = validate_email_payload(json_body())
    result = predictor().predict_email(data["sender"], data["reply_to"], data["subject"], data["body"])
    digest = fingerprint(data["sender"], data["subject"], data["body"])
    scan = _store(user, "email", email_preview(data["subject"]), digest, result)
    return jsonify(scan.to_dict()), 201


# ---------------------------------------------------------------- history

@api.get("/scans")
@jwt_required()
def list_scans():
    user = current_user()
    if not user:
        return _error("unauthorized", "Account no longer exists.", 401)
    page = positive_int(request.args.get("page"), 1, 10_000, "page")
    per_page = positive_int(request.args.get("per_page"), 20, 50, "per_page")
    query = db.select(Scan).where(Scan.user_id == user.id).order_by(Scan.created_at.desc(), Scan.id.desc())
    pagination = db.paginate(query, page=page, per_page=per_page, error_out=False)
    return jsonify(
        items=[s.to_dict() for s in pagination.items],
        page=pagination.page,
        per_page=per_page,
        total=pagination.total,
    )


@api.get("/scans/<int:scan_id>")
@jwt_required()
def get_scan(scan_id: int):
    scan = _owned_scan(scan_id)
    if not scan:
        return _error("not_found", "Scan not found.", 404)
    return jsonify(scan.to_dict())


@api.delete("/scans/<int:scan_id>")
@jwt_required()
def delete_scan(scan_id: int):
    scan = _owned_scan(scan_id)
    if not scan:
        return _error("not_found", "Scan not found.", 404)
    db.session.delete(scan)
    db.session.commit()
    return "", 204


@api.delete("/scans")
@jwt_required()
def delete_all_scans():
    user = current_user()
    if not user:
        return _error("unauthorized", "Account no longer exists.", 401)
    result = db.session.execute(db.delete(Scan).where(Scan.user_id == user.id))
    db.session.commit()
    return jsonify(deleted=result.rowcount)


def register_error_handlers(app):
    @app.errorhandler(ValidationError)
    def validation_error(exc: ValidationError):
        return _error("validation_error", exc.message, 400, exc.field)

    @app.errorhandler(ModelNotReady)
    def model_not_ready(exc):
        return _error("model_unavailable", str(exc), 503)

    @app.errorhandler(404)
    def not_found(_):
        return _error("not_found", "Resource not found.", 404)

    @app.errorhandler(405)
    def method_not_allowed(_):
        return _error("method_not_allowed", "Method not allowed.", 405)

    @app.errorhandler(413)
    def too_large(_):
        return _error("payload_too_large", "Request body is too large.", 413)

    @app.errorhandler(429)
    def rate_limited(_):
        return _error("rate_limited", "Too many requests. Wait a moment and try again.", 429)

    @app.errorhandler(Exception)
    def unexpected(exc):
        from werkzeug.exceptions import HTTPException

        if isinstance(exc, HTTPException):
            return _error(exc.name.lower().replace(" ", "_"), exc.description, exc.code or 500)
        current_app.logger.exception("Unhandled error")
        db.session.rollback()
        return _error("server_error", "Something went wrong on our side.", 500)
