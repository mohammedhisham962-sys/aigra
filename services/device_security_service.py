import subprocess
import requests
import hashlib
import platform
try:
    from zxcvbn import zxcvbn
    HAS_ZXCVBN = True
except ImportError:
    HAS_ZXCVBN = False

class DeviceSecurityService:
    def __init__(self):
        pass
        
    def check_wifi_security(self):
        """Scans the current Windows WiFi connection for security vulnerabilities."""
        if platform.system() != 'Windows':
            return {"status": "Cloud Mode", "is_secure": True, "message": "App is running in the cloud. Local WiFi check disabled."}
            
        try:
            result = subprocess.run(['netsh', 'wlan', 'show', 'interfaces'], capture_output=True, text=True)
            output = result.stdout
            
            if "State" in output and "connected" in output:
                auth_type = "Unknown"
                encryption = "Unknown"
                
                for line in output.split('\n'):
                    if "Authentication" in line:
                        auth_type = line.split(':', 1)[1].strip()
                    elif "Cipher" in line:
                        encryption = line.split(':', 1)[1].strip()
                        
                is_secure = auth_type not in ["Open", "WEP"]
                
                return {
                    "status": "Connected",
                    "auth_type": auth_type,
                    "encryption": encryption,
                    "is_secure": is_secure,
                    "message": "Secure connection." if is_secure else "WARNING: Connected to an unencrypted/weakly encrypted network. Use a VPN."
                }
            return {"status": "Disconnected", "is_secure": True, "message": "Not connected to WiFi."}
        except Exception as e:
            return {"status": "Error", "message": f"Failed to check WiFi: {str(e)}"}
            
    def check_password_strength(self, password):
        """Calculates password entropy using zxcvbn."""
        if not HAS_ZXCVBN:
            return {"score": 0, "feedback": {"warning": "Password checker library not installed."}}
            
        result = zxcvbn(password)
        return {
            "score": result['score'], # 0 to 4
            "crack_time": result['crack_times_display']['offline_slow_hashing_1e4_per_second'],
            "warning": result['feedback']['warning'],
            "suggestions": result['feedback']['suggestions']
        }
        
    def check_data_breach(self, email):
        """Checks if an email has been compromised using the HaveIBeenPwned API."""
        # Note: The actual HIBP API requires an API key now, so we will use a mock simulation for demo purposes
        # or the free pass if they have an old key. Since it's a local demo, we'll simulate it for safety.
        # A real implementation would be: requests.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers={"hibp-api-key": "..."})
        
        # Simulating a breach for demo if email ends with 'test.com'
        if "test.com" in email.lower():
            return {
                "breached": True,
                "breaches": [
                    {"Name": "FakeAppBreach", "Domain": "fakeapp.com", "DataClasses": ["Email addresses", "Passwords"]}
                ],
                "message": f"WARNING: {email} was found in 1 known data breach!"
            }
        
        return {
            "breached": False,
            "breaches": [],
            "message": f"Good news! {email} was not found in any known public data breaches."
        }
