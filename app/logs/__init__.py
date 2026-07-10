from flask import Blueprint

logs_bp = Blueprint('logs', __name__, template_folder='../templates/logs')

from . import routes  # noqa: E402, F401
