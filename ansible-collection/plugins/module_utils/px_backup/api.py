from __future__ import absolute_import, division, print_function
__metaclass__ = type

import requests

class PXBackupClient:
    """
    Common API client for PX-Backup modules.

    This class provides a unified HTTP client interface for interacting with the PX-Backup API.
    It handles authentication, SSL/TLS certificate management, and standardized error handling
    across all PX-Backup Ansible modules.

    Features:
    - Bearer token authentication
    - Flexible SSL/TLS certificate validation
    - Mutual TLS authentication support
    - Automatic JSON request/response handling
    - Enhanced error reporting with server details
    - URL normalization and endpoint construction

    The client is designed to be reusable across different PX-Backup operations while
    maintaining consistent security and error handling practices.
    """

    def __init__(self, api_url, token, validate_certs=True, ca_cert=None, client_cert=None, client_key=None):
        """
        Initialize the PX-Backup API client with connection and authentication parameters.

        This constructor configures the HTTP client for secure communication with the
        PX-Backup API server, including authentication credentials and SSL/TLS settings.

        Args:
            api_url (str): Base URL of the PX-Backup API server. Examples:
                          - "https://px-backup.example.com:10002"
                          - "px-backup-server.local:10002" (http:// will be added)
                          - "192.168.1.100:10002"
            token (str): Bearer authentication token for API access. This should be
                        a valid JWT token obtained from PX-Backup authentication.
            validate_certs (bool, optional): Enable SSL certificate validation.
                                            Defaults to True. Set to False only for
                                            development with self-signed certificates.
            ca_cert (str, optional): Path to custom CA certificate file for validating
                                    server certificates signed by private CAs.
            client_cert (str, optional): Path to client certificate file for mutual
                                        TLS authentication when required by the server.
            client_key (str, optional): Path to client private key file corresponding
                                       to the client certificate.

        Note:
            - If api_url doesn't include a protocol, 'http://' will be prepended
            - For production environments, always use HTTPS with certificate validation
            - Client certificates are only needed when the server requires mutual TLS
        """
        # Normalize the API URL by ensuring it has a protocol prefix
        # This allows users to specify URLs with or without http:// or https://
        if not api_url.startswith(('http://', 'https://')):
            api_url = f"http://{api_url}"

        # Store the base API URL with trailing slashes removed for consistent URL construction
        self.api_url = api_url.rstrip('/')

        # Configure standard HTTP headers for all API requests
        # Content-Type: Tells the server we're sending JSON data
        # Authorization: Bearer token for API authentication
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {token}"
        }

        # Store SSL/TLS and authentication configuration for use in requests
        self.validate_certs = validate_certs  # Whether to validate server certificates
        self.ca_cert = ca_cert                # Custom CA certificate file path
        self.client_cert = client_cert        # Client certificate for mutual TLS
        self.client_key = client_key          # Client private key for mutual TLS

    def make_request(self, method, endpoint, data=None, cert=None, params=None):
        """
        Execute an HTTP request to the PX-Backup API with comprehensive error handling.

        This method is the core communication function that handles all HTTP interactions
        with the PX-Backup API server. It constructs URLs, manages SSL/TLS settings,
        processes authentication, and provides detailed error reporting.

        The method automatically handles:
        - URL construction and normalization
        - SSL/TLS certificate validation configuration
        - Client certificate authentication setup
        - JSON serialization of request data
        - JSON deserialization of response data
        - HTTP status code validation
        - Enhanced error message generation

        Args:
            method (str): HTTP method for the request. Supported methods include:
                         'GET' - Retrieve data from the server
                         'POST' - Create new resources
                         'PUT' - Update existing resources (full replacement)
                         'PATCH' - Partial update of existing resources
                         'DELETE' - Remove resources from the server

            endpoint (str): API endpoint path relative to the base URL. Examples:
                           - '/api/v1/clusters' - List all clusters
                           - 'backup/schedules' - Backup schedules endpoint
                           - '/v1/backups/{backup_id}' - Specific backup resource
                           Leading slashes are optional and will be handled automatically.

            data (dict, optional): Request payload data for POST/PUT/PATCH operations.
                                  This dictionary will be automatically serialized to JSON.
                                  Example: {'name': 'my-backup', 'schedule': '0 2 * * *'}

            cert (str/bool, optional): Override SSL certificate validation for this request.
                                      - str: Path to specific CA certificate file
                                      - True: Use default system certificate validation
                                      - False: Disable certificate validation
                                      - None: Use client's default configuration

            params (dict, optional): URL query parameters as key-value pairs.
                                    Will be URL-encoded and appended to the request.
                                    Example: {'status': 'active', 'limit': 50}

        Returns:
            dict: Parsed JSON response from the API server. The structure varies
                 depending on the specific endpoint called. Common patterns include:
                 - Single resource: {'id': '123', 'name': 'resource-name', ...}
                 - Resource list: {'items': [...], 'total': 10, 'page': 1}
                 - Operation result: {'success': True, 'message': 'Operation completed'}

        Raises:
            Exception: Raised when any aspect of the HTTP request fails, including:
                      - Network connectivity issues (DNS resolution, connection timeout)
                      - SSL/TLS certificate validation failures
                      - HTTP error status codes (400 Bad Request, 401 Unauthorized, etc.)
                      - Invalid JSON in request or response
                      - Server-side errors (500 Internal Server Error, etc.)

                      The exception message includes detailed information about the
                      failure, including server error responses when available.

        Example Usage:
            # GET request to list all backup schedules
            schedules = client.make_request('GET', '/api/v1/backup-schedules')

            # POST request to create a new backup schedule
            schedule_data = {
                'name': 'daily-backup',
                'schedule': '0 2 * * *',
                'backup_location': 'my-s3-bucket'
            }
            result = client.make_request('POST', '/api/v1/backup-schedules', data=schedule_data)

            # GET request with query parameters to filter results
            active_backups = client.make_request(
                'GET',
                '/api/v1/backups',
                params={'status': 'running', 'limit': 10}
            )

            # DELETE request to remove a specific resource
            client.make_request('DELETE', f'/api/v1/backup-schedules/{schedule_id}')
        """
        # Construct the complete API URL by combining base URL with the endpoint
        # Strip leading slashes from endpoint to avoid double slashes in the URL
        url = f"{self.api_url}/{endpoint.lstrip('/')}"

        # Determine SSL/TLS certificate verification strategy
        if cert is not None:
            # Per-request override provided
            verify = cert
        elif not self.validate_certs:
            # SSL validation disabled - ignore all certificates
            verify = False
        elif self.ca_cert:
            # SSL validation enabled with custom CA
            verify = self.ca_cert
        else:
            # SSL validation enabled with system certificates
            verify = True

        # Configure client certificate authentication for mutual TLS
        # This is required when the server demands client certificate authentication
        client_cert_tuple = None
        if self.client_cert and self.client_key:
            # Both certificate and private key files are provided
            # Create a tuple as expected by the requests library for mutual TLS
            client_cert_tuple = (self.client_cert, self.client_key)
        elif self.client_cert:
            # Only certificate file is provided (private key might be embedded in the cert file)
            # Some certificate formats include both the certificate and private key
            client_cert_tuple = self.client_cert

        try:
            # Execute the HTTP request with all configured parameters
            # The requests library handles the actual HTTP communication
            response = requests.request(
                method=method,                # HTTP method (GET, POST, PUT, DELETE, etc.)
                url=url,                     # Complete URL constructed from base + endpoint
                headers=self.headers,        # Authentication and content-type headers
                json=data,                   # Request payload (automatically serialized to JSON)
                params=params,               # URL query parameters (automatically URL-encoded)
                verify=verify,               # SSL/TLS certificate verification setting
                cert=client_cert_tuple       # Client certificate for mutual TLS authentication
            )

            # Check for HTTP error status codes (4xx and 5xx responses)
            # This will raise an HTTPError exception for unsuccessful status codes
            # allowing us to handle both network errors and HTTP errors consistently
            response.raise_for_status()

            # Parse the JSON response body and return it as a Python dictionary
            # This assumes the API always returns valid JSON (standard for REST APIs)
            return response.json()

        except requests.exceptions.RequestException as e:
            # Comprehensive error handling for all types of request failures
            # This includes network errors, SSL errors, HTTP errors, and JSON parsing errors

            # Start with the basic error message from the exception
            error_msg = str(e)

            # Try to extract additional error details from the server response
            # Many APIs return structured error information in the response body
            if hasattr(e, 'response') and e.response is not None:
                try:
                    # Attempt to parse the error response as JSON
                    # This often contains detailed error codes, messages, and context
                    error_detail = e.response.json()
                    error_msg = f"{error_msg}: {error_detail}"
                except ValueError:
                    # If JSON parsing fails, include the raw response text
                    # This ensures we don't lose any error information from the server
                    error_msg = f"{error_msg}: {e.response.text}"

            # Re-raise as a generic Exception with enhanced error information
            # This provides a consistent error interface for all calling code
            raise Exception(f"API request failed: {error_msg}")