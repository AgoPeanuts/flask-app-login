from flask import Blueprint, render_template
from flask_login import login_required

# create blueprint
main = Blueprint('main', __name__)

@main.route('/', methods=['GET'])
@login_required
def index():
    """
    Main Module for members' pages
    """
    return render_template('main/index.html')