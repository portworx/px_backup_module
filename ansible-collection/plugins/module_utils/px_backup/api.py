from __future__ import absolute_import, division, print_function
__metaclass__ = type

import requests

class PXBackupClient:
    """Common API client for PX-Backup modules"""
    def __init__(self, api_url, token, validate_certs=True):
        # Add protocol if not present
        if not api_url.startswith(('http://', 'https://')):
            api_url = f"http://{api_url}"  # or https:// if you prefer
        self.api_url = api_url.rstrip('/')
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {token}"
        }
        self.validate_certs = validate_certs

    def make_request(self, method, endpoint, data=None, cert=None, params=None):
        """Make HTTP request to PX-Backup API"""
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        
        if cert is None:
            cert = self.validate_certs

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self.headers,
                json=data,
                params=params,
                verify=cert
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            # Improve error handling
            error_msg = str(e)
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    error_msg = f"{error_msg}: {error_detail}"
                except ValueError:
                    error_msg = f"{error_msg}: {e.response.text}"
            raise Exception(f"API request failed: {error_msg}")