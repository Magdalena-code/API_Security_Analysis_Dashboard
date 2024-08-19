import datetime
import subprocess
import re
import os

import psycopg2
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask.cli import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for the API

app.config['UPLOAD_FOLDER'] = os.getenv('INPUT')
output_directory = os.getenv('OUTPUT')

# Connection parameters
db_params_1 = {
    'database': os.getenv('DB1_NAME', 'api_dashboard'),
    'user': os.getenv('DB1_USER', 'postgres'),
    'password': os.getenv('DB1_PASSWORD', 'postgres'),
    'host': os.getenv('DB1_HOST', 'localhost'),
    'port': os.getenv('DB1_PORT', '5432'),
}

db_params_2 = {
    'database': os.getenv('DB2_NAME', 'user_database'),
    'user': os.getenv('DB2_USER', 'postgres'),
    'password': os.getenv('DB2_PASSWORD', 'postgres'),
    'host': os.getenv('DB2_HOST', 'localhost'),
    'port': os.getenv('DB2_PORT', '5432'),
}

def clean_up(file_path):
    try:
        os.remove(file_path)
        print(f"Successfully deleted the file: {file_path}")
    except Exception as e:
        print(f"Failed to delete the file {file_path}: {e}")

def connect_to_db(db_params):
    try:
        connection = psycopg2.connect(**db_params)
        print("Connected to the database!")
        cursor = connection.cursor()
        return connection, cursor
    except Exception as e:
        print(f"Error: {e}")
        return None, None

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'json', 'yaml', 'yml'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    connection, cursor = connect_to_db(db_params_1)
    if connection is None or cursor is None:
        return jsonify({"error": "Unable to connect to the database"})

    try:
        scan_url = request.args.get('scan_url')
        scan_id = request.args.get('scan_id')

        query = """
            SELECT DISTINCT scan_id, scan_date, scan_url, tool_name, vuln_name, vuln_number, prio_name, 
                            owasp_name, v.vuln_id, scan_active, vuln_description, vuln_new 
            FROM scans 
            JOIN vulnerabilities v ON scan_id = vuln_scan 
            JOIN tools ON tool_id = scan_tool 
            JOIN vuln_owasp vo ON v.vuln_id = vo.vuln_id 
            JOIN owasp_categories o ON o.owasp_id = vo.owasp_id 
            JOIN priorities ON vuln_priority = prio_id
        """

        if scan_url:
            query += " WHERE scan_url = %s;"
            cursor.execute(query, (scan_url,))
        elif scan_id:
            query += " WHERE scan_id = %s;"
            cursor.execute(query, (scan_id,))
        else:
            query += " ORDER BY scan_date DESC;"
            cursor.execute(query)

        rows = cursor.fetchall()

        data = []
        for row in rows:
            found_vulnerabilities = {
                "scan_id": row[0],
                "scan_date": row[1],
                "scan_url": row[2],
                "tool_name": row[3],
                "vuln_name": row[4],
                "vuln_number": row[5],
                "prio_name": row[6],
                "owasp_name": row[7],
                "vuln_id": row[8],
                "scan_active": row[9],
                "vuln_description": row[10],
                "vuln_new": row[11]
            }
            data.append(found_vulnerabilities)

        return jsonify(data)

    except Exception as e:
        return jsonify({"error": f"Error executing query: {e}"})

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

@app.route('/scans', methods=['GET'])
def get_scans():
    connection, cursor = connect_to_db(db_params_1)
    if connection is None or cursor is None:
        return jsonify({"error": "Unable to connect to the database"})

    try:
        scan_url = request.args.get('scan_url')
        scan_date = request.args.get('scan_date')

        query = """
        SELECT DISTINCT scan_id, scan_date, scan_url, tool_name, scan_active 
        FROM scans 
        JOIN tools ON tool_id = scan_tool
        WHERE 1=1
        """

        if scan_url:
            query += " AND scan_url = %s"
        if scan_date:
            query += " AND DATE(scan_date) = %s"

        query += " ORDER BY scan_id DESC"

        params = []
        if scan_url:
            params.append(scan_url)
        if scan_date:
            params.append(scan_date)

        cursor.execute(query, params)
        rows = cursor.fetchall()

        data = []
        for row in rows:
            found_scans = {
                "scan_id": row[0],
                "scan_date": row[1],
                "scan_url": row[2],
                "tool_name": row[3],
                "active_scan": row[4]
            }
            data.append(found_scans)

        return jsonify(data)

    except Exception as e:
        return jsonify({"error": f"Error executing query: {e}"})

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

@app.route('/run-passive-scan', methods=['POST'])
def run_docker_passive():
    data = request.json
    if 'url' not in data:
        return jsonify({"error": "URL is missing"}), 400

    url = data['url']
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    json_report_file = f'api-passive-scan-report_{timestamp}.json'
    print({output_directory})

    docker_command = (
        f'docker run -v {output_directory}:/zap/wrk -t owasp/zap2docker-stable zap-baseline.py '
        f'-g api-passive-scan.conf -t {url} -J {json_report_file}'
    )

    try:
        print("Starting scan")
        result = subprocess.run(docker_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        stdout_output = result.stdout.decode('utf-8')
        stderr_output = result.stderr.decode('utf-8')

        print("STDOUT:", stdout_output)
        print("STDERR:", stderr_output)

        success_pattern = r'Total of \d+ URLs'
        match = re.search(success_pattern, stdout_output)

        if result.returncode == 0 or (match and int(re.search(r'\d+', match.group()).group()) > 0):
            print("Scan completed successfully")
            print({output_directory})
            return jsonify({"message": "URL successfully scanned"}), 200
        else:
            print("Scan failed with errors")
            return jsonify({"error": "Scan failed", "details": stderr_output}), 500
    except subprocess.TimeoutExpired:
        print("Scan timed out")
        return jsonify({"error": "Scan timed out"}), 500
    except Exception as e:
        print("Exception during scan:", e)
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route('/run-active-scan', methods=['POST'])
def run_docker_active():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        print(f"File uploaded successfully: {file_path}")

        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        json_report_file = f'api-active-scan-report_{timestamp}.json'

        docker_command = (
            f'docker run -v {output_directory}:/zap/wrk -t owasp/zap2docker-stable zap-api-scan.py '
            f'-t /zap/wrk/openapi/{filename} -f openapi -J {json_report_file}'
        )

        print("Docker command:", docker_command)

        try:
            print("Starting active scan")
            result = subprocess.run(docker_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)  # Adding a timeout

            stdout_output = result.stdout.decode('utf-8')
            stderr_output = result.stderr.decode('utf-8')

            print("STDOUT:", stdout_output)
            print("STDERR:", stderr_output)

            success_pattern = r'Total of \d+ URLs'
            match = re.search(success_pattern, stdout_output)

            if result.returncode == 0 or (match and int(re.search(r'\d+', match.group()).group()) > 0):
                print("Scan completed successfully")
                return jsonify({"message": "URL successfully scanned"}), 200
            else:
                print("Scan failed with errors")
                return jsonify({"error": "Scan failed", "details": stderr_output}), 500
        except subprocess.TimeoutExpired:
            print("Scan timed out")
            return jsonify({"error": "Scan timed out"}), 500
        except Exception as e:
            print("Exception during scan:", e)
            return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
    else:
        return jsonify({"error": "File type not allowed"}), 400

@app.route('/vulnerability_trend', methods=['GET'])
def get_vulnerability_trend():
    connection, cursor = connect_to_db(db_params_1)
    if connection is None or cursor is None:
        return jsonify({"error": "Unable to connect to the database"})

    try:
        scan_url = request.args.get('scan_url')
        if not scan_url:
            return jsonify({"error": "Missing scan_url parameter"}), 400

        print(f"Received scan_url: {scan_url}")  # Debugging information

        query = """
            SELECT scan_date, owasp_name, COUNT(v.vuln_id) as vuln_count, scan_active
            FROM scans s
            JOIN vulnerabilities v ON s.scan_id = v.vuln_scan 
            JOIN vuln_owasp vo ON v.vuln_id = vo.vuln_id 
            JOIN owasp_categories o ON o.owasp_id = vo.owasp_id 
            WHERE s.scan_url = %s
            GROUP BY scan_date, owasp_name, scan_active
            ORDER BY scan_date ASC;
        """
        cursor.execute(query, (scan_url,))
        rows = cursor.fetchall()

        data = {}
        for row in rows:
            scan_date = row[0].strftime('%Y-%m-%d')
            owasp_name = row[1]
            vuln_count = row[2]
            scan_active = row[3]

            if scan_date not in data:
                data[scan_date] = {
                    "vuln_counts": {},
                    "scan_active": scan_active
                }
            data[scan_date]["vuln_counts"][owasp_name] = vuln_count

        response_data = {
            "scan_date": [],
            "scan_active": [],
            **{owasp_name: [] for _, owasp_name, _, _ in rows}
        }

        for scan_date in sorted(data.keys()):
            response_data["scan_date"].append(scan_date)
            response_data["scan_active"].append(data[scan_date]["scan_active"])

            for owasp_name in response_data.keys():
                if owasp_name not in ["scan_date", "scan_active"]:
                    response_data[owasp_name].append(data[scan_date]["vuln_counts"].get(owasp_name, 0))

        return jsonify(response_data)
    except Exception as e:
        return jsonify({"error": f"Error executing query: {e}"})
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

@app.route('/customisation', methods=['GET'])
def get_customisation():
    connection, cursor = connect_to_db(db_params_2)
    if connection is None or cursor is None:
        return jsonify({"error": "Unable to connect to the database"})

    try:
        user_id = request.args.get('user_id')
        owasp_cat = request.args.get('owasp_cat')

        base_query = "SELECT * FROM riskometer_weights"
        conditions = []
        params = []

        if user_id:
            conditions.append("user_id = %s")
            params.append(user_id)

        if owasp_cat:
            conditions.append("owasp_cat = %s")
            params.append(owasp_cat)

        if conditions:
            base_query += " WHERE " + " AND ".join(conditions)

        order_by = "owasp_cat"
        base_query += f" ORDER BY {order_by};"

        cursor.execute(base_query, params)
        rows = cursor.fetchall()

        data = []
        for row in rows:
            found_customisation = {
                "user_id": row[0],
                "owasp_cat": row[1],
                "weight": row[2],
            }
            data.append(found_customisation)

        def extract_number(owasp_cat):
            match = re.search(r'\d+', owasp_cat)
            return int(match.group()) if match else float('inf')

        sorted_data = sorted(data, key=lambda x: extract_number(x['owasp_cat']))

        return jsonify(sorted_data)

    except Exception as e:
        return jsonify({"error": f"Error executing query: {e}"})

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

@app.route('/customisation', methods=['POST'])
def update_customisation():
    data = request.json
    connection, cursor = connect_to_db(db_params_2)
    if connection is None or cursor is None:
        return jsonify({"error": "Unable to connect to the database"})

    try:
        for customisation in data:
            query = """
                UPDATE riskometer_weights
                SET weight = %s
                WHERE user_id = %s AND owasp_cat = %s;
            """
            cursor.execute(query, (customisation['weight'], customisation['user_id'], customisation['owasp_cat']))
        connection.commit()
        return jsonify({"status": "success"})

    except Exception as e:
        return jsonify({"error": f"Error executing query: {e}"})

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
