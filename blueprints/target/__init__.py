from flask import Blueprint

target_bp = Blueprint("target", __name__, template_folder="../../templates")

from . import routes  # noqa: E402, F401

