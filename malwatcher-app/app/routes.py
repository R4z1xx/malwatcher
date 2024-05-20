from flask import Blueprint, render_template, request, jsonify
from tomlkit import load, dumps
from urllib.parse import urljoin
import requests


main_blueprint = Blueprint('main', __name__)

@main_blueprint.route('/')
def index():
    return render_template('index.html')

@main_blueprint.route('/report', methods=['POST'])
def check_ioc():
    ioc = request.form.get('ioc')
    if not ioc:
        return jsonify({"error": "No IOC provided"}), 400
    
    with open('/app/config/config.toml', 'r') as fp:
        config = load(fp)
    worker_url = urljoin(f"{config['worker']['worker-protocol']}://{config['worker']['worker-name']}:{config['worker']['worker-port']}/", 'check')
    response = requests.post(worker_url, json={"ioc": ioc})
    results = response.json()
    
    return render_template('report.html', results=results)

@main_blueprint.route('/settings')
def settings():
    with open('/app/config/config.toml', 'r') as fp:
        config = load(fp)
    return render_template('settings.html', config=config)

@main_blueprint.route('/update_settings', methods=['POST'])
def update_settings():
    vt_key = request.form.get('vt-key')
    vt_enter = True if request.form.get('vt-enterprise') else False
    otx_key = request.form.get('otx-key')
    abuse_key = request.form.get('abuseipdb-key')
    log_level = request.form.get('log-level')

    with open('/app/config/config.toml', 'r') as fp:
        config = load(fp)
    config['virustotal-api']['vt-key'] = vt_key
    config['virustotal-api']['vt-enterprise'] = vt_enter
    config['otx-api']['otx-key'] = otx_key
    config['abuseipdb-api']['abuseipdb-key'] = abuse_key
    config['logging']['log-level'] = log_level
    config = dumps(config)
    with open('/app/config/config.toml', 'w') as f:
        f.write(config)
    return settings()