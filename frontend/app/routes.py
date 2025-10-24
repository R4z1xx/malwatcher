from flask import Blueprint, render_template, request, jsonify, redirect
from yaml import safe_load
from urllib.parse import urljoin, unquote, quote
import requests

main_blueprint = Blueprint('main', __name__)

def _load_config():
    with open('/app/config/global.yaml', 'r') as fp:
        config = safe_load(fp)
    return config

@main_blueprint.route('/')
def index():
    return render_template('index.html')

@main_blueprint.route('/report/<path:ioc>', methods=['GET'])
def check_ioc(ioc):
    try:
        decoded_ioc = unquote(ioc)
        response = requests.post('http://worker:8080/check', json={"ioc": decoded_ioc})
        response.raise_for_status()
        results = response.json()
    except requests.exceptions.RequestException as e:
        return render_template("report.html", results={"error": "Worker service unavailable"})
    return render_template('report.html', results=results)


@main_blueprint.route('/report', methods=['POST'])
def handle_check():
    ioc = request.form.get('ioc')
    
    if not ioc:
        return jsonify({"error": "No IOC provided"}), 400
    
    ioc = ioc.strip()
    return redirect("/report/{}".format(quote(ioc, safe='')))

@main_blueprint.route('/settings')
def settings():
    return render_template('index.html')