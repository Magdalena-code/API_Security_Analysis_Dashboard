from random import random
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

# Queries to create tables
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

def ensure_owasp_categories_in_db(cursor, connection, owasp_categories):
    if connection is None or cursor is None:
        print("Database connection or cursor is invalid.")
        return False

    for owasp_id, owasp_name, owasp_description in owasp_categories:
        try:
            query = f"SELECT COUNT(*) FROM owasp_categories WHERE owasp_name = %s;"
            cursor.execute(query, (owasp_name,))
            result = cursor.fetchone()

            count = result[0] if result else 0

            if count == 0:
                insert_query = "INSERT INTO owasp_categories (owasp_id, owasp_name, owasp_description) VALUES (%s, %s, %s);"
                cursor.execute(insert_query, (owasp_id, owasp_name, owasp_description))
                connection.commit()
                print(f"Inserted OWASP category: {owasp_name}")
            else:
                print(f"OWASP category already exists: {owasp_name}")

        except Exception as e:
            print(f"Error: {e}")
            return False

    return True

def ensure_priority_labels_are_in_db(cursor, connection, priorities):
    if connection is None or cursor is None:
        print("Database connection or cursor is invalid.")
        return False

    for prio_id, prio_name, prio_description in priorities:
        try:
            query = f"SELECT COUNT(*) FROM priorities WHERE prio_name = %s;"
            cursor.execute(query, (prio_name,))
            result = cursor.fetchone()

            count = result[0] if result else 0

            if count == 0:
                insert_query = "INSERT INTO priorities (prio_id, prio_name, prio_description) VALUES (%s, %s, %s);"
                cursor.execute(insert_query, (prio_id, prio_name, prio_description))
                connection.commit()
                print(f"Inserted priority: {prio_name}")
            else:
                print(f"Priority already exists: {prio_name}")

        except Exception as e:
            print(f"Error: {e}")
            return False

    return True

def ensure_owasp_categories_in_riskometer(cursor, connection, owasp_categories_for_riskometer):
    if connection is None or cursor is None:
        print("Database connection or cursor is invalid.")
        return False

    for user_id, owasp_name, weight in owasp_categories_for_riskometer:
        try:
            query = f"SELECT COUNT(*) FROM riskometer_weights WHERE owasp_cat = %s;"
            cursor.execute(query, (owasp_name,))
            result = cursor.fetchone()

            count = result[0] if result else 0

            if count == 0:
                insert_query = "INSERT INTO riskometer_weights (user_id, owasp_cat, weight) VALUES (%s, %s, %s);"
                cursor.execute(insert_query, (user_id, owasp_name, weight))
                connection.commit()
                print(f"Inserted OWASP category: {owasp_name}")
            else:
                print(f"OWASP category already exists: {owasp_name}")

        except Exception as e:
            print(f"Error: {e}")
            return False

    return True

def ensure_standard_user_in_db(cursor, connection, user):
    if connection is None or cursor is None:
        print("Database connection or cursor is invalid.")
        return False
    for user_name, user_email, user_password in user:
        try:
            # Check if the user already exists
            query = f"SELECT COUNT(*) FROM users WHERE user_name = %s;"
            cursor.execute(query, (user_name,))
            result = cursor.fetchone()

            count = result[0] if result else 0

            if count == 0:
                insert_query = "INSERT INTO users (user_name, user_email, user_password) VALUES (%s, %s, %s);"
                cursor.execute(insert_query, (user_name, user_email, user_password))
                connection.commit()
                print(f"Inserted standard user: {user_name}")
            else:
                print(f"Standard user already in database: {user_name}")

        except Exception as e:
            print(f"Error: {e}")
            return False

    return True

# Sample data
owasp_categories = [
    (1, "API1 - Broken Object Level Authorization", "APIs expose endpoints handling object IDs, creating a wide attack surface due to inadequate object level authorization checks."),
    (2, "API2 - Broken Authentication", "Authentication mechanisms are often incorrectly implemented, enabling attackers to compromise tokens or exploit flaws to assume identities."),
    (3, "API3 - Broken Object Property Level Authorization", "Combines excessive data exposure and mass assignment issues due to improper authorization at the object property level."),
    (4, "API4 - Unrestricted Resource Consumption", "API requests consume resources like bandwidth and CPU, with attacks potentially leading to Denial of Service or increased costs."),
    (5, "API5 - Broken Function Level Authorization", "Complex policies and unclear role separations often result in authorization flaws, allowing attackers access to restricted functions."),
    (6, "API6 - Unrestricted Access to Sensitive Business Flows", "Vulnerable APIs expose business flows without limits, risking excessive use or automation that harms business operations."),
    (7, "API7 - Server Side Request Forgery", "SSRF occurs when APIs fetch remote resources without validating URIs, allowing attackers to direct requests to unintended destinations."),
    (8, "API8 - Security Misconfiguration", "APIs suffer from complex configurations that are often mishandled, leading to vulnerabilities due to poor security practices."),
    (9, "API9 - Improper Inventory Management", "APIs expose more endpoints than traditional apps, necessitating thorough documentation and updated inventories to avoid exposing deprecated or debug endpoints."),
    (10, "API10 - Unsafe Consumption of APIs", "Developers often trust third-party API data, adopting weaker security standards, which attackers exploit by targeting these third-party integrations."),
    (0, "No Threat", "Just an overall information is given")
]

priorities = [
    (0, "Informational", "Informational not classified as a vulnerability"),
    (1, "Low", "Low priority"),
    (2, "Medium", "Medium priority"),
    (3, "High", "High priority")
]

owasp_categories_for_riskometer = [
    (1, "API1 - Broken Object Level Authorization", 10),
    (1, "API2 - Broken Authentication", 10),
    (1, "API3 - Broken Object Property Level Authorization", 10),
    (1, "API4 - Unrestricted Resource Consumption", 10),
    (1, "API5 - Broken Function Level Authorization", 10),
    (1, "API6 - Unrestricted Access to Sensitive Business Flows", 10),
    (1, "API7 - Server Side Request Forgery", 10),
    (1, "API8 - Security Misconfiguration", 10),
    (1, "API9 - Improper Inventory Management", 10),
    (1, "API10 - Unsafe Consumption of APIs", 10)
]

user = [
    ("Melanie Mustermann", "example@email.com", "test")
]

# Database connection and table creation
connection_1, cursor_1 = connect_to_db(db_params_1)
execute_query(connection_1, create_dashboard_table_query)
ensure_owasp_categories_in_db(cursor_1, connection_1, owasp_categories)
ensure_priority_labels_are_in_db(cursor_1, connection_1, priorities)

if connection_1:
    cursor_1.close()
    connection_1.close()

connection_2, cursor_2 = connect_to_db(db_params_2)
execute_query(connection_2, create_user_table_query)
ensure_standard_user_in_db(cursor_2, connection_2, user)
ensure_owasp_categories_in_riskometer(cursor_2, connection_2, owasp_categories_for_riskometer)

if connection_2:
    cursor_2.close()
    connection_2.close()
