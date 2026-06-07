from flask import Flask, render_template, request, jsonify
import subprocess
import json

app = Flask(__name__)

# Not-noisy function to run Trivy scan
def run_trivy_scan(image_name):
    try:
        result = subprocess.run(
            ["trivy", "image", "--ignore-unfixed", "--scanners", "vuln", "-f", "json", image_name],
            capture_output=True, text=True, check=True
        )
        scan_data = json.loads(result.stdout)  # Parse JSON output
        return scan_data
    except subprocess.CalledProcessError as e:
        return {"error": f"Trivy scan failed: {e.stderr}"}

@app.route("/", methods=["GET", "POST"])
def index():
    vulnerabilities = None

    if request.method == "POST":
        image_name = request.form.get("image", "vulnerables/web-dvwa")  # Default image
        scan_results = run_trivy_scan(image_name)
        vulnerabilities = scan_results.get("Results", [])

    return render_template("index.html", vulnerabilities=vulnerabilities)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6699)

##
##
