import http.client
import json
import ssl
import os
import re
import cli
import socket

# --- Configuration ---
AWX_HOST_SOCKET = "192.168.1.116:30443"
AWX_SCHEME = "http" # Change to "https" for production AWX
AWX_ENDPOINT = "/api/v2/workflow_job_templates/12/launch/" # Ensure trailing slash if API requires it
API_TOKEN = "dEUuqVGy7LBxAsW2JTH3gQFqZO4qeY" # Use an API token which only has job execution rights.
VERIFY_SSL = False
CONNECTION_TIMEOUT = 30


# --- Script Logic ---

def launch_awx_job(host_socket, scheme, endpoint, token, payload, verify_ssl=True, timeout=30):
    """Launches an AWX Job Template via the API using http.client."""

    print(f"Attempting to launch job via API: {scheme}://{host_socket}{endpoint}")

    # Separate host and port if port is specified
    host = host_socket
    port = None
    if ':' in host_socket:
        host, port_str = host_socket.split(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            print(f"Error: Invalid port specified in host_socket: {port_str}")
            return False, "Invalid port"

    # Prepare headers
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json; charset=utf-8"
    }

    # Encode payload
    try:
        json_payload_bytes = json.dumps(payload).encode('utf-8')
        headers["Content-Length"] = str(len(json_payload_bytes))
    except Exception as e:
        print(f"Error encoding JSON payload: {e}")
        return False, f"JSON Encoding Error: {e}"

    conn = None
    try:
        # Create connection object based on scheme
        if scheme.lower() == "https":
            ssl_context = None
            if not verify_ssl:
                # WARNING: Disables SSL certificate verification - less secure!
                ssl_context = ssl._create_unverified_context()
                print("WARNING: SSL certificate verification is DISABLED.")
            else:
                ssl_context = ssl.create_default_context()

            # Use default HTTPS port if not specified
            if port is None:
                port = 443
            conn = http.client.HTTPSConnection(host, port=port, timeout=timeout, context=ssl_context)

        elif scheme.lower() == "http":
            # Use default HTTP port if not specified
            if port is None:
                port = 80
            conn = http.client.HTTPConnection(host, port=port, timeout=timeout)
        else:
            print(f"Error: Unsupported scheme: {scheme}. Use 'http' or 'https'.")
            return False, f"Unsupported scheme: {scheme}"

        # Send the POST request
        print("Sending POST request to AWX API...")
        conn.request("POST", endpoint, body=json_payload_bytes, headers=headers)

        # Get the response
        response = conn.getresponse()
        status_code = response.status
        response_body = response.read().decode('utf-8') # Read body regardless of status

        print(f"AWX API Response Status Code: {status_code}")
        print(f"AWX API Response Body: {response_body}")

        # Check for successful launch (usually 201 Created)
        if status_code == 201:
            print("Job launched successfully!")
            try:
                # Attempt to parse response JSON to get job ID if needed
                response_json = json.loads(response_body)
                job_id = response_json.get('job')
                if job_id:
                    print(f"Launched Job ID: {job_id}")
            except json.JSONDecodeError:
                print("(Could not parse response body as JSON)")
            return True, response_body
        else:
            print(f"Failed to launch job (Status: {status_code}).")
            return False, response_body

    except socket.timeout:
        print(f"Error: Connection timed out after {timeout} seconds.")
        return False, "Connection Timeout"
    except ConnectionRefusedError:
        print(f"Error: Connection refused by server {host}:{port}. Is AWX running and accessible?")
        return False, "Connection Refused"
    except Exception as e:
        print(f"An unexpected error occurred during API call: {e}")
        return False, f"Unexpected Error: {e}"
    finally:
        # Ensure connection is closed
        if conn:
            conn.close()
            print("Connection closed.")

def get_ip_address():
    output = cli.execute("show ip interface brief | include Vlan100")
    match = re.search(r"\d+\.\d+\.\d+\.\d+", output)

    if match:
        ip_address = match.group()
        print(f"IP Address for Management VLAN is: {ip_address}")
        return ip_address
    else:
        print("IP Address not found.")
        return "IP Address not found!"

# --- Main Execution ---
if __name__ == "__main__":

    IP_Address = get_ip_address()
    print(IP_Address)

    payload_data = {
        "extra_vars": {
            "ztp_hostname": "test_hostname",
            "ztp_ip_address": IP_Address
    }
}
    
    # Make the API call
    success, result = launch_awx_job(
        AWX_HOST_SOCKET,
        AWX_SCHEME,
        AWX_ENDPOINT,
        API_TOKEN,
        payload_data,
        VERIFY_SSL,
        CONNECTION_TIMEOUT
    )

    if success:
        print("\nZTP Script: API Trigger successful.")
        # Potentially exit script with success code
    else:
        print("\nZTP Script: API Trigger failed.")
        # Potentially exit script with failure code or attempt retry/logging