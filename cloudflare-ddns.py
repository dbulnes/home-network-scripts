#!/usr/bin/env python3

import requests
import logging
import time
import boto3
import io
from datetime import datetime, timedelta
from pathlib import Path
import os
from logging.handlers import HTTPHandler
import json
import akeyless
import stat

class NewRelicHandler(HTTPHandler):
    def __init__(self, license_key):
        super().__init__(
            host="log-api.newrelic.com",
            url="/log/v1",
            method="POST",
            secure=True
        )
        self.license_key = license_key
        self.formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    def mapLogRecord(self, record):
        if record.exc_info:
            message = self.formatter.formatException(record.exc_info)
        else:
            message = record.getMessage()

        log_entry = {
            "timestamp": int(record.created * 1000),
            "message": message,
            "log.level": record.levelname,
            "logger.name": record.name,
            "service.name": "cloudflare-ddns",
            "hostname": os.uname().nodename
        }

        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)

        return log_entry

    def emit(self, record):
        try:
            data = self.mapLogRecord(record)
            headers = {
                "Api-Key": self.license_key,
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                f"https://{self.host}{self.url}",
                headers=headers,
                json=data,
                timeout=5
            )
            
            if response.status_code != 202:
                print(f"New Relic logging failed: Status {response.status_code}, Response: {response.text}")
        except Exception as e:
            print(f"Error sending logs to New Relic: {str(e)}")
            self.handleError(record)

class CloudflareDDNS:
    def __init__(self):
        self.cache_file = Path.home() / '.cloudflare-ddns' / '.secrets_cache'
        
        # Try to load from cache first, if fails then initialize Akeyless
        if not self._load_from_cache():
            # Initialize Akeyless client
            self.akeyless_api = self._init_akeyless()
            # Retrieve secrets from Akeyless
            self._load_secrets()
            # Save to cache
            self._save_to_cache()
        
        # API endpoints
        self.cf_api_base = "https://api.cloudflare.com/client/v4"
        self.ip_check_urls = [
            "https://api.ipify.org?format=text",
            "https://ifconfig.me/ip",
            "https://api.ipify.org",
            "https://icanhazip.com",
            "https://ident.me"
        ]
        
        # Setup local logging
        log_path = Path.home() / '.cloudflare-ddns'
        log_path.mkdir(exist_ok=True)
        self.log_file = log_path / 'ddns.log'
        
        # Setup R2 buffer
        self.r2_buffer = io.StringIO()
        
        # Configure logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Remove any existing handlers
        self.logger.handlers = []
        
        # Create formatters
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # File handler
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setFormatter(formatter)
        
        # R2 buffer handler
        buffer_handler = logging.StreamHandler(self.r2_buffer)
        buffer_handler.setFormatter(formatter)
        
        # New Relic handler
        newrelic_handler = NewRelicHandler(self.new_relic_license_key)
        
        # Add all handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(buffer_handler)
        self.logger.addHandler(newrelic_handler)
        
        # Initial log messages with extra context
        self.logger.info("DDNS Service Starting", extra={
            'extra_fields': {
                'domain': self.domain,
                'event_type': 'service_start'
            }
        })
        
        # Initialize R2 client
        self.s3_client = boto3.client(
            's3',
            endpoint_url=f'https://{self.r2_account_id}.r2.cloudflarestorage.com',
            aws_access_key_id=self.r2_access_key_id,
            aws_secret_access_key=self.r2_secret_access_key
        )

    def _load_from_cache(self):
        """Try to load secrets from cache file"""
        try:
            if not self.cache_file.exists():
                return False
                
            # Check if cache file is older than last boot time
            boot_time = Path('/proc/stat').stat().st_mtime
            if self.cache_file.stat().st_mtime < boot_time:
                return False

            with open(self.cache_file, 'r') as f:
                cached_secrets = json.load(f)

            # Load all secrets from cache
            self.zone_id = cached_secrets['zone_id']
            self.dns_record_id = cached_secrets['dns_record_id']
            self.auth_token = cached_secrets['auth_token']
            self.domain = "vpn.vidbuln.es"
            self.r2_account_id = cached_secrets['r2_account_id']
            self.r2_access_key_id = cached_secrets['r2_access_key_id']
            self.r2_secret_access_key = cached_secrets['r2_secret_access_key']
            self.r2_bucket_name = "trash-bucket"
            self.r2_log_prefix = "ddns_logs/"
            self.new_relic_license_key = cached_secrets['new_relic_license_key']

            return True

        except Exception as e:
            print(f"Failed to load from cache: {str(e)}")
            return False

    def _save_to_cache(self):
        """Save secrets to cache file"""
        try:
            # Create directory if it doesn't exist
            self.cache_file.parent.mkdir(exist_ok=True)
            
            cached_secrets = {
                'zone_id': self.zone_id,
                'dns_record_id': self.dns_record_id,
                'auth_token': self.auth_token,
                'r2_account_id': self.r2_account_id,
                'r2_access_key_id': self.r2_access_key_id,
                'r2_secret_access_key': self.r2_secret_access_key,
                'new_relic_license_key': self.new_relic_license_key
            }

            # Write to cache file with restricted permissions
            with open(self.cache_file, 'w') as f:
                json.dump(cached_secrets, f)
            
            # Set file permissions to 600 (user read/write only)
            os.chmod(self.cache_file, stat.S_IRUSR | stat.S_IWUSR)

        except Exception as e:
            print(f"Failed to save to cache: {str(e)}")

    def _init_akeyless(self):
        """Initialize Akeyless client with authentication"""
        try:
            # Get credentials from environment
            access_id = os.environ.get('AKEYLESS_ACCESS_ID')
            access_key = os.environ.get('AKEYLESS_ACCESS_KEY')
            
            if not access_id or not access_key:
                raise ValueError("AKEYLESS_ACCESS_ID or AKEYLESS_ACCESS_KEY environment variables not set")
            
            # Configure API client
            configuration = akeyless.Configuration(host="https://api.akeyless.io")
            
            # Create API client instance
            with akeyless.ApiClient(configuration) as api_client:
                api = akeyless.V2Api(api_client)
                
                print(f"Authenticating with access_id: {access_id}")  # Debug print
                
                # Authenticate
                auth_body = akeyless.Auth(
                    access_id=access_id,
                    access_key=access_key
                )
                
                try:
                    auth_res = api.auth(body=auth_body)
                    self.akeyless_token = auth_res.token
                    print("Authentication successful")  # Debug print
                    return api
                except akeyless.ApiException as e:
                    print(f"Authentication failed: {e.body}")  # Debug print
                    raise
                    
        except Exception as e:
            raise Exception(f"Failed to initialize Akeyless client: {str(e)}")

    def _get_secret(self, secret_path):
        """Retrieve a secret from Akeyless"""
        try:
            body = akeyless.GetSecretValue(
                names=[secret_path],
                token=self.akeyless_token
            )
            result = self.akeyless_api.get_secret_value(body=body)
            
            if isinstance(result, dict) and secret_path in result:
                return result[secret_path]
            else:
                raise ValueError(f"Unexpected response format: {result}")
                
        except akeyless.ApiException as e:
            raise Exception(f"Failed to retrieve secret {secret_path}: {str(e)}")

    def _load_secrets(self):
        """Load all required secrets from Akeyless"""
        try:
            # Cloudflare credentials
            self.zone_id = self._get_secret("/cloudflare-zone-id")
            self.dns_record_id = self._get_secret("/cloudflare-vpn.vidbuln.es-dns-record-id")
            self.auth_token = self._get_secret("/cloudflare-auth-token")
            self.domain = "vpn.vidbuln.es"  # This appears to be a constant value
            
            # R2 credentials
            self.r2_account_id = self._get_secret("/r2-account-id")
            self.r2_access_key_id = self._get_secret("/r2-access-key-id")
            self.r2_secret_access_key = self._get_secret("/r2-bucket-secret-access-key")
            self.r2_bucket_name = "trash-bucket"  # This appears to be a constant value
            self.r2_log_prefix = "ddns_logs/"  # This appears to be a constant value
            
            # New Relic credentials
            self.new_relic_license_key = self._get_secret("/new-relic-license-key")
            
            if not self.new_relic_license_key:
                raise ValueError("New Relic license key not found in Akeyless")
                
        except Exception as e:
            raise Exception(f"Failed to load secrets from Akeyless: {str(e)}")

    def upload_logs_to_r2(self):
        """Upload current log buffer to R2 and delete old logs."""
        try:
            # Upload logs to R2
            self._upload_current_logs_to_r2()
        except Exception as e:
            self.logger.error("Failed to upload/delete logs to R2", extra={
                'extra_fields': {
                    'error': str(e),
                    'event_type': 'r2_upload_error'
                }
            })

    def _upload_current_logs_to_r2(self):
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        log_key = f"{self.r2_log_prefix}{timestamp}.log"

        log_contents = self.r2_buffer.getvalue()

        self.s3_client.put_object(
            Bucket=self.r2_bucket_name,
            Key=log_key,
            Body=log_contents.encode('utf-8'),
            ContentType='text/plain'
        )

        self.r2_buffer.truncate(0)
        self.r2_buffer.seek(0)

        self.logger.info("Logs uploaded to R2", extra={
            'extra_fields': {
                'log_key': log_key,
                'event_type': 'r2_upload_success'
            }
        })

    def get_public_ip(self):
        """Get current public IP address using multiple services for redundancy"""
        for url in self.ip_check_urls:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if self.is_valid_ip(ip):
                        self.logger.info("Public IP retrieved", extra={
                            'extra_fields': {
                                'ip_address': ip,
                                'source_url': url,
                                'event_type': 'ip_check_success'
                            }
                        })
                        return ip
                    else:
                        self.logger.warning("Invalid IP format received", extra={
                            'extra_fields': {
                                'received_ip': ip,
                                'source_url': url,
                                'event_type': 'ip_check_error'
                            }
                        })
            except requests.RequestException as e:
                self.logger.warning("Failed to get IP from service", extra={
                    'extra_fields': {
                        'error': str(e),
                        'source_url': url,
                        'event_type': 'ip_check_error'
                    }
                })
        
        self.logger.error("All IP checks failed", extra={
            'extra_fields': {
                'event_type': 'ip_check_failure'
            }
        })
        return None

    def is_valid_ip(self, ip):
        """Basic IPv4 validation"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            return all(0 <= int(part) <= 255 for part in parts)
        except (AttributeError, TypeError, ValueError):
            return False

    def get_dns_record(self):
        """Get current DNS record from Cloudflare"""
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json"
        }
        
        try:
            url = f"{self.cf_api_base}/zones/{self.zone_id}/dns_records/{self.dns_record_id}"
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            if data["success"]:
                record = data["result"]
                current_ip = record["content"]
                is_proxied = record["proxied"]
                self.logger.info("DNS record retrieved", extra={
                    'extra_fields': {
                        'current_ip': current_ip,
                        'is_proxied': is_proxied,
                        'event_type': 'dns_record_check'
                    }
                })
                if not is_proxied:
                    self.logger.warning("DNS record is not proxied", extra={
                        'extra_fields': {
                            'event_type': 'dns_proxy_warning'
                        }
                    })
                return current_ip, is_proxied
                self.logger.error("Failed to get DNS record", extra={
                    'extra_fields': {
                        'errors': data['errors'],
                        'event_type': 'dns_record_error'
                    }
                })
                return None, None
                
        except requests.RequestException as e:
            self.logger.error("Error getting DNS record", extra={
                'extra_fields': {
                    'error': str(e),
                    'event_type': 'dns_record_error'
                }
            })
            return None, None

    def update_dns_record(self, new_ip):
        """Update Cloudflare DNS record with new IP"""
        headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json"
        }
        
        data = {
            "type": "A",
            "name": self.domain,
            "content": new_ip,
            "ttl": 1,
            "proxied": True
        }
        
        try:
            url = f"{self.cf_api_base}/zones/{self.zone_id}/dns_records/{self.dns_record_id}"
            response = requests.put(url, headers=headers, json=data, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            if result["success"]:
                self.logger.info("DNS record updated", extra={
                    'extra_fields': {
                        'new_ip': new_ip,
                        'is_proxied': True,
                        'event_type': 'dns_update_success'
                    }
                })
                return True
            else:
                self.logger.error("Failed to update DNS record", extra={
                    'extra_fields': {
                        'errors': result['errors'],
                        'event_type': 'dns_update_error'
                    }
                })
                return False
                
        except requests.RequestException as e:
            self.logger.error("Error updating DNS record", extra={
                'extra_fields': {
                    'error': str(e),
                    'event_type': 'dns_update_error'
                }
            })
            return False

    def run(self):
        """Main execution logic"""
        self.logger.info("Starting DNS update check", extra={
            'extra_fields': {
                'event_type': 'update_check_start'
            }
        })
        
        try:
            # Get current public IP
            current_ip = self.get_public_ip()
            if not current_ip:
                return
            
            # Get current DNS record
            dns_ip, is_proxied = self.get_dns_record()
            if not dns_ip:
                return
            
            # Update if IP has changed or proxy status is wrong
            if current_ip != dns_ip or not is_proxied:
                self.logger.info("Update needed", extra={
                    'extra_fields': {
                        'current_ip': current_ip,
                        'dns_ip': dns_ip,
                        'is_proxied': is_proxied,
                        'event_type': 'update_needed'
                    }
                })
                self.update_dns_record(current_ip)
            else:
                self.logger.info("No update needed", extra={
                    'extra_fields': {
                        'ip': current_ip,
                        'event_type': 'no_update_needed'
                    }
                })
                
        finally:
            # Always try to upload logs at the end
            self.upload_logs_to_r2()

if __name__ == "__main__":
    ddns = CloudflareDDNS()
    ddns.run()
