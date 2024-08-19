import psycopg2
from psycopg2 import OperationalError

# Connection parameters
db_params_1 = {
    'database': 'api_dashboard',
    'user': 'postgres',
    'password': 'postgres',
    'host': 'localhost',
    'port': '5432',
}

db_params_2 = {
    'database': 'user_database',
    'user': 'postgres',
    'password': 'postgres',
    'host': 'localhost',
    'port': '5432',
}

def connect_to_db(db_params):
    try:
        connection = psycopg2.connect(**db_params)
        print("Connected to the database!")
        cursor = connection.cursor()
        return connection, cursor
    except Exception as e:
        print(f"Error: {e}")
        return None, None

def execute_query(connection, query):
    connection.autocommit = True
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        print("Tables created successfully")
    except OperationalError as e:
        print(f"The error '{e}' occurred")

connection_1, cursor_1 = connect_to_db(db_params_1)
connection_2, cursor_2 = connect_to_db(db_params_2)

create_dashboard_table_query = """
CREATE TABLE IF NOT EXISTS owasp_categories (
    owasp_id INTEGER PRIMARY KEY,
    owasp_name TEXT NOT NULL UNIQUE,
    owasp_description TEXT
);

CREATE TABLE IF NOT EXISTS tools (
    tool_id SERIAL PRIMARY KEY,
    tool_name TEXT NOT NULL,
    tool_description TEXT
);

CREATE TABLE IF NOT EXISTS priorities (
    prio_id INTEGER PRIMARY KEY,
    prio_name TEXT NOT NULL,
    prio_description TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id SERIAL PRIMARY KEY,
    scan_date TIMESTAMP NOT NULL,
    scan_url TEXT NOT NULL,
    scan_active BOOLEAN DEFAULT FALSE,
    scan_tool INTEGER references tools(tool_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id SERIAL PRIMARY KEY,
    vuln_name TEXT NOT NULL,
    vuln_scan INTEGER references scans(scan_id) ON DELETE CASCADE,      
    vuln_priority INTEGER references priorities(prio_id),
    vuln_number INTEGER,
    vuln_description TEXT,
    vuln_new BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS vuln_owasp (
    vuln_id INTEGER references vulnerabilities(vuln_id) ON DELETE CASCADE,
    owasp_id INTEGER references owasp_categories(owasp_id),
    PRIMARY KEY (vuln_id, owasp_id)
);
"""

create_user_table_query = """
CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    user_name TEXT NOT NULL,
    user_email TEXT NOT NULL UNIQUE,
    user_password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS riskometer_weights (
    user_id INTEGER references users(user_id) ON DELETE CASCADE,
    owasp_cat VARCHAR(100) NOT NULL,
    weight INTEGER NOT NULL,
    PRIMARY KEY (user_id, owasp_cat)
);
"""

execute_query(connection_1, create_dashboard_table_query)
execute_query(connection_2, create_user_table_query)

if connection_1:
    cursor_1.close()
    connection_1.close()

if connection_2:
    cursor_2.close()
    connection_2.close()
