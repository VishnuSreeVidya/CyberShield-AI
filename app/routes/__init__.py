from flask import Blueprint

main_bp = Blueprint('main', __name__)

from . import routes  # noqa: E402, F401

from .api import register_api_routes
register_api_routes(main_bp)
