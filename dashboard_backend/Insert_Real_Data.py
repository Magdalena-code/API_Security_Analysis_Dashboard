import json
import psycopg2
import os
import re

from flask.cli import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime, timedelta
import pandas as pd
import openpyxl


load_dotenv()
path = os.getenv('OUTPUT')
if path is None or not os.path.isdir(path):
    print(f"Error: The directory {path} does not exist or is not set.")
    exit(1)

# Connection parameters
db_params = {
    'database': 'api_dashboard',
    'user': 'postgres',
    'password': 'postgres',
    'host': 'localhost',
    'port': '5432',
}

def connect_to_db():
    try:
        connection = psycopg2.connect(**db_params)
        print("Connected to the database!")
        return connection
    except Exception as e:
        print(f"Error: {e}")
        return None

class MyHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory or not event.src_path.endswith('.json'):
            return
        print(f"Processing new file: {event.src_path}")
        self.process_json(event.src_path)

    def process_json(self, file_path):
        with open(file_path, 'r') as file:
            data = json.load(file)
        self.insert_into_db(data, file_path)

    def insert_into_db(self, data, file_path):
        connection = connect_to_db()
        if connection is None:
            return
        cursor = connection.cursor()

        vuln_owasp_mapping = pd.read_excel('owasp_mapping.xlsx')

        scan_tool_name = data.get('@programName')
        scan_date = datetime.strptime(data.get('@generated'), '%a, %d %b %Y %H:%M:%S')

        for site_info in data.get('site', []):
            base_url = site_info.get('@name')
            port = site_info.get('@port')

            if ':' in base_url:
                scan_url = base_url
            else:
                if base_url.endswith('/'):
                    scan_url = f"{base_url[:-1]}:{port}"
                else:
                    scan_url = f"{base_url}:{port}"

            # Check if the scan date is older than the newest scan date in the database
            cursor.execute("""
                    SELECT MAX(scan_date) FROM scans WHERE scan_url = %s;
                """, (scan_url,))
            max_scan_date = cursor.fetchone()[0]

            # Workaround so no two scans on the same day and URL can be done
            if max_scan_date is not None:
                max_scan_date = max_scan_date.replace(hour=0, minute=0, second=0, microsecond=0)
                scan_date_check = scan_date.replace(hour=0, minute=0, second=0, microsecond=0)

            if max_scan_date is not None and scan_date_check <= max_scan_date:
                print(
                    f"Scan date {scan_date} is older or done at the same day as the most recent scan date {max_scan_date}. Skipping insertion.")
                continue

            query = "SELECT tool_id FROM tools WHERE tool_name = %s;"
            cursor.execute(query, (scan_tool_name,))
            result = cursor.fetchone()
            if result:
                scan_tool = result[0]
                print(f"Tool '{scan_tool_name}' already exists in the database.")
            else:
                cursor.execute("""INSERT INTO tools (tool_name) VALUES (%s);
                            """, (scan_tool_name,))

                query = "SELECT tool_id FROM tools WHERE tool_name = %s;"
                cursor.execute(query, (scan_tool_name,))
                result = cursor.fetchone()
                scan_tool = result[0]

            scan_active = 'active' in file_path.lower()

            cursor.execute("""
                                    INSERT INTO scans (scan_tool, scan_date, scan_url, scan_active) 
                                    VALUES (%s, %s, %s, %s);
                                """, (scan_tool, scan_date, scan_url, scan_active))

            query = "SELECT scan_id FROM scans WHERE scan_tool = %s AND scan_date = %s AND scan_url = %s;"
            cursor.execute(query, (scan_tool, scan_date, scan_url))
            result = cursor.fetchone()
            if result:
                vuln_scan = result[0]
            else:
                raise ValueError(f"No scan found for tool: {scan_tool_name} and date: {scan_date} and URL: {scan_url}")

            one_month_ago = scan_date - timedelta(days=30)

            for alert in site_info.get('alerts', []):
                vuln_name = alert['alert']
                vuln_prio = alert['riskcode']
                vuln_description = alert['desc']
                vuln_number = alert['count']

                # Check if the same vulnerability exists in the last scan for the same URL within the last month
                cursor.execute("""
                    SELECT v.vuln_id
                    FROM vulnerabilities v
                    JOIN scans s ON v.vuln_scan = s.scan_id
                    WHERE s.scan_url = %s AND s.scan_date < %s AND s.scan_date >= %s AND v.vuln_name = %s
                    ORDER BY s.scan_date DESC
                    LIMIT 1;
                """, (scan_url, scan_date, one_month_ago, vuln_name))
                last_vuln = cursor.fetchone()

                vuln_new = last_vuln is None

                cursor.execute("""
                    INSERT INTO vulnerabilities (vuln_name, vuln_priority, vuln_description, vuln_number, vuln_scan, vuln_new) 
                    VALUES (%s, %s, %s, %s, %s, %s);
                """, (vuln_name, vuln_prio, vuln_description, vuln_number, vuln_scan, vuln_new))

                query = "SELECT vuln_id FROM vulnerabilities join scans on scan_id = vuln_scan WHERE vuln_name = %s ORDER BY vuln_id DESC LIMIT 1;"
                cursor.execute(query, (vuln_name,))
                result = cursor.fetchone()
                if result:
                    vuln_id = result[0]
                else:
                    vuln_id = None

                matching_rows = vuln_owasp_mapping[vuln_owasp_mapping['Vulnerability'].str.lower() == vuln_name.lower()]
                if matching_rows.empty:
                    raise ValueError(f"No corresponding OWASP data found for vulnerability: {vuln_name}")

                owasp_data = matching_rows['OWASP'].iloc[0]

                if pd.notna(owasp_data):
                    if isinstance(owasp_data, int):
                        owasp_ids = [owasp_data]
                    else:
                        owasp_ids = [int(id.strip()) for id in owasp_data.split(',')]

                    for owasp_id in owasp_ids:
                        print("OWASP ID: ", owasp_id, "vuln_id: ", vuln_id)
                        # Insert each pair into the database
                        cursor.execute("""
                                        INSERT INTO vuln_owasp (vuln_id, owasp_id) 
                                        VALUES (%s, %s);
                                    """, (vuln_id, owasp_id))

        connection.commit()
        cursor.close()
        connection.close()
        print(f"Data inserted for file: {file_path}")

if __name__ == "__main__":
    event_handler = MyHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=False)
    observer.start()
    print("Monitoring for new files...")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    print("Stopped monitoring.")
