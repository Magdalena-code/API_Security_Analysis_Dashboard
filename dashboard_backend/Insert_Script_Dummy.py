import random
import psycopg2
from datetime import datetime, timedelta

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
        cursor = connection.cursor()
        return connection, cursor
    except Exception as e:
        print(f"Error: {e}")

def get_recent_scan_id(cursor):
    try:
        query = "SELECT scan_id FROM scans ORDER BY scan_date DESC LIMIT 1;"
        cursor.execute(query)
        result = cursor.fetchone()
        if result:
            return result[0]
        else:
            return None
    except Exception as e:
        print(f"An error occurred while retrieving the recent scan ID: {e}")
        return None

def chooseDummyToolName():
    random_number = random.randint(1, 3)
    if random_number == 1:
        return "Random API Scanner"
    elif random_number == 2:
        return "Dummy API Scanner"
    elif random_number == 3:
        return "Some API Scanner"
    else:
        return None

def get_tool_id(cursor, dummy_toolname):
    try:
        query = "SELECT tool_id FROM tools WHERE tool_name = %s;"
        cursor.execute(query, (dummy_toolname,))
        result = cursor.fetchone()
        if result:
            return result[0]
        else:
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def is_tool_already_in_db(cursor, connection, dummy_toolname):
    if connection is None or cursor is None:
        return False

    try:
        query = "SELECT COUNT(*) FROM tools WHERE tool_name = %s;"
        cursor.execute(query, (dummy_toolname,))
        count = cursor.fetchone()[0]

        if count == 0:
            insert_query = "INSERT INTO tools (tool_name, tool_description) VALUES (%s, %s);"
            cursor.execute(insert_query, (dummy_toolname, 'This is a dummy tool.'))
            connection.commit()
            print(f"Inserted tool: {dummy_toolname}")
        else:
            print(f"Tool already exists: {dummy_toolname}")
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def insert_scan(cursor, connection, scans):
    if connection is None or cursor is None:
        print("Database connection or cursor is invalid.")
        return False

    for scan_date, scan_tool, scan_url in scans:
        is_tool_already_in_db(cursor, connection, scan_tool)
        tool_id = get_tool_id(cursor, scan_tool)
        try:
            insert_query = "INSERT INTO scans (scan_date, scan_tool, scan_url) VALUES (%s, %s, %s);"
            cursor.execute(insert_query, (scan_date, tool_id, scan_url))
            connection.commit()
            print(f"Inserted scan with tool {scan_tool} at {scan_date}")
        except Exception as e:
            print(f"Error: {e}")
            return False
    return True

def insert_vulnerabilities(cursor, connection, vulnerabilities):
    if connection is None or cursor is None:
        print("Database connection or cursor is invalid.")
        return True

    vuln_scan = get_recent_scan_id(cursor)
    inserted_vuln_ids = []
    vuln_new = True
    for vuln_name, vuln_priority, vuln_number, vuln_owasp, vuln_description in vulnerabilities:
        try:
            insert_query = "INSERT INTO vulnerabilities (vuln_name, vuln_scan, vuln_priority, vuln_number, vuln_description, vuln_new) VALUES (%s, %s, %s, %s, %s, %s) RETURNING vuln_id;"
            cursor.execute(insert_query, (vuln_name, vuln_scan, vuln_priority, vuln_number, vuln_description, vuln_new))
            connection.commit()
            inserted_vuln_id = cursor.fetchone()[0]
            inserted_vuln_ids.append((inserted_vuln_id, vuln_owasp))
            print(f"Inserted vulnerability: {vuln_name}")
        except Exception as e:
            print(f"Error: {e}")
            return False
    return inserted_vuln_ids

def insert_owasp_vuln_connection(cursor, connection, inserted_vuln_ids):
    if connection is None or cursor is None:
        print("Database connection or cursor is invalid.")
        return False


    for vuln_id, owasp_ids in inserted_vuln_ids:
        try:
            for owasp_id in owasp_ids:
                insert_owasp_vuln = "INSERT INTO vuln_owasp (vuln_id, owasp_id) VALUES (%s, %s);"
                cursor.execute(insert_owasp_vuln, (vuln_id, owasp_id))
            connection.commit()
        except Exception as e:
            print(f"An error occurred: {e}")
            connection.rollback()
            return False
    return True

now = datetime.now()
one_day_ago = now + timedelta(days=11)
formatted_date = one_day_ago.strftime("%Y-%m-%d %H:%M:%S")
scans = [(formatted_date, chooseDummyToolName(), "https://www.example.com")]

# scans= [
#     (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), chooseDummyToolName(), "https://www.example.com")
#  ]

vulnerabilities= [
    #("Content Security Policy (CSP) Header Not Set", 2, 10, {8}, 'The Content-Security-Policy header is not set.'),
    ("SQL Injection", 3, 1, {1, 3}, 'SQL Injection is a code injection technique that might destroy your database.'),
    #("Bypassing 403", 2, 5, {1, 5}, 'The server is returning a 403 Forbidden status code.'),
    # ("Server Leaks Version Information via Server HTTP Response Header Field", 1, 18, {8}, 'The server is leaking version information via the Server HTTP response header field.'),
    # ("A Client Error response code was returned by the server", 0, 1714, {8}, 'A client error response code was returned by the server.'),
    #("Cross-Site Scripting (XSS) - Reflected", 3, 4, {8}, 'Cross-Site Scripting (XSS) is a vulnerability that allows an attacker to inject malicious scripts into web pages.'),
    # ("Application Error Discloser", 1, 9, {8,10}, 'Application Error Discloser is a vulnerability that allows an attacker to see the error messages of the application.'),
    #("Session Management Response Identified", 1, 3, {2}, 'Session Management Response Identified is a vulnerability that allows an attacker to see the session management response.'),
    #("Hidden File Found", 2, 1, {9}, 'Is a vulnerability that allows an attacker to see the hidden files.'),
    #("Dangerous JS Functions", 3, 2, {1}, 'This vulnerability can lead to a Cross-Site Scripting (XSS) attack.'),
    # ("Modern Web Application", 0, 1, {0}, 'This is a modern web application.'),
]

def insert_everything():
    connection, cursor = connect_to_db()
    insert_scan(cursor, connection, scans)
    inserted_vuln_ids = insert_vulnerabilities(cursor, connection, vulnerabilities)
    insert_owasp_vuln_connection(cursor, connection, inserted_vuln_ids)
    cursor.close()
    connection.close()

insert_everything()
