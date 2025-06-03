#!/usr/bin/env python3
"""
EPIC Server Security Testing Suite
Comprehensive automated testing for all OWASP vulnerability categories
"""

import requests
import json
import time
import base64
import sys
from typing import Dict, List
import uuid

class SecurityTester:
    def __init__(self, base_url: str = "http://localhost:3010"):
        self.base_url = base_url
        self.session = requests.Session()
        self.results = {"tests": [], "summary": {}}
        
    def log_result(self, category: str, test: str, status: str, details: str = ""):
        """Log test result"""
        result = {
            "category": category,
            "test": test,
            "status": status,
            "details": details,
            "timestamp": time.time()
        }
        self.results["tests"].append(result)
        icon = "PASS" if status == "PASS" else "FAIL" if status == "VULNERABLE" else "WARN"
        print(f"[{icon}] {category}: {test} - {status}")
        if details: print(f"      {details}")
    
    def test_input_validation(self):
        """Test Category 1: Input Validation Vulnerabilities"""
        print("\nTesting Input Validation...")
        
        # SQL Injection Tests
        sql_payloads = ["' OR '1'='1", "admin'; DROP TABLE users; --", "' UNION SELECT * FROM users --"]
        for payload in sql_payloads:
            try:
                response = self.session.post(f"{self.base_url}/api/user/{payload}/salts", timeout=5)
                if response.status_code == 500:
                    self.log_result("Input Validation", f"SQL Injection ({payload[:20]}...)", "VULNERABLE", 
                                  "Server error suggests SQL injection vulnerability")
                else:
                    self.log_result("Input Validation", f"SQL Injection ({payload[:20]}...)", "PASS")
            except Exception as e:
                self.log_result("Input Validation", f"SQL Injection ({payload[:20]}...)", "ERROR", str(e))
        
        # XSS Tests
        xss_payloads = ["<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>"]
        for payload in xss_payloads:
            try:
                response = self.session.post(f"{self.base_url}/api/auth/register", 
                    json={"username": payload, "auth_salt": "test", "enc_salt": "test", 
                          "auth_key": "test", "encrypted_mek": "test", "public_key": {}, "user_data_hmac": "test"})
                if payload in response.text:
                    self.log_result("Input Validation", "XSS Protection", "VULNERABLE", "XSS payload reflected in response")
                else:
                    self.log_result("Input Validation", "XSS Protection", "PASS")
            except Exception as e:
                self.log_result("Input Validation", "XSS Protection", "ERROR", str(e))
    
    def test_authentication(self):
        """Test Category 2: Authentication & Session Management"""
        print("\nTesting Authentication...")
        
        # Rate Limiting Test
        print("   Testing rate limiting...")
        rate_limited = False
        for i in range(8):
            try:
                response = self.session.post(f"{self.base_url}/api/auth/login",
                    json={"username": "test_user", "auth_key": "wrong_key", "otp": "000000"})
                if response.status_code == 429:
                    rate_limited = True
                    break
                time.sleep(0.1)
            except Exception:
                break
        
        if rate_limited:
            self.log_result("Authentication", "Rate Limiting", "PASS", "Rate limiting active after multiple attempts")
        else:
            self.log_result("Authentication", "Rate Limiting", "VULNERABLE", "No rate limiting detected")
        
        # Session Security Test
        try:
            response = self.session.post(f"{self.base_url}/api/auth/login",
                json={"username": "test", "auth_key": "test", "otp": "123456"})
            if "session" in response.text and "totp_secret" not in response.text:
                self.log_result("Authentication", "Session Management", "PASS", "Session tokens generated without exposing secrets")
            elif "totp_secret" in response.text:
                self.log_result("Authentication", "TOTP Secret Exposure", "VULNERABLE", "CRITICAL: TOTP secret exposed in response")
            else:
                self.log_result("Authentication", "Session Management", "PASS")
        except Exception as e:
            self.log_result("Authentication", "Session Management", "ERROR", str(e))
    
    def test_access_control(self):
        """Test Category 3: Access Control"""
        print("\nTesting Access Control...")
        
        # Unauthorized Endpoint Access
        protected_endpoints = ["/api/files/", "/api/user/profile"]
        for endpoint in protected_endpoints:
            try:
                response = self.session.get(f"{self.base_url}{endpoint}")
                if response.status_code == 200:
                    self.log_result("Access Control", f"Unauthorized Access ({endpoint})", "VULNERABLE", 
                                  "Endpoint accessible without authentication")
                elif response.status_code in [401, 403]:
                    self.log_result("Access Control", f"Unauthorized Access ({endpoint})", "PASS")
                else:
                    self.log_result("Access Control", f"Unauthorized Access ({endpoint})", "INFO", f"Status: {response.status_code}")
            except Exception as e:
                self.log_result("Access Control", f"Unauthorized Access ({endpoint})", "ERROR", str(e))
        
        # IDOR Testing
        test_ids = ["00000000-0000-0000-0000-000000000001", "99999999-9999-9999-9999-999999999999"]
        for test_id in test_ids:
            try:
                response = self.session.get(f"{self.base_url}/api/files/{test_id}/metadata")
                if response.status_code == 200:
                    self.log_result("Access Control", f"IDOR Test ({test_id[:8]}...)", "VULNERABLE", 
                                  "Unauthorized object access successful")
                elif response.status_code in [401, 403, 404]:
                    self.log_result("Access Control", f"IDOR Test ({test_id[:8]}...)", "PASS")
            except Exception as e:
                self.log_result("Access Control", f"IDOR Test ({test_id[:8]}...)", "ERROR", str(e))
    
    def test_injection(self):
        """Test Category 4: Injection Vulnerabilities"""
        print("\nTesting Injection Attacks...")
        
        # Command Injection
        cmd_payloads = ["; ls -la", "| cat /etc/passwd", "&& whoami", "$(id)"]
        for payload in cmd_payloads:
            try:
                response = self.session.get(f"{self.base_url}/api/user/{payload}/salts")
                if any(indicator in response.text.lower() for indicator in ["root:", "bin:", "uid=", "total"]):
                    self.log_result("Injection", f"Command Injection ({payload})", "VULNERABLE", 
                                  "Command execution detected in response")
                else:
                    self.log_result("Injection", f"Command Injection ({payload})", "PASS")
            except Exception as e:
                self.log_result("Injection", f"Command Injection ({payload})", "ERROR", str(e))
        
        # Path Traversal
        path_payloads = ["../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//....//etc//passwd"]
        for payload in path_payloads:
            try:
                response = self.session.get(f"{self.base_url}/api/files/{payload}")
                if "root:" in response.text or "bin:" in response.text:
                    self.log_result("Injection", f"Path Traversal ({payload[:15]}...)", "VULNERABLE", 
                                  "Path traversal successful")
                else:
                    self.log_result("Injection", f"Path Traversal ({payload[:15]}...)", "PASS")
            except Exception as e:
                self.log_result("Injection", f"Path Traversal ({payload[:15]}...)", "ERROR", str(e))
    
    def test_security_configuration(self):
        """Test Category 5: Security Misconfiguration"""
        print("\nTesting Security Configuration...")
        
        # Security Headers Check
        try:
            response = self.session.get(f"{self.base_url}/")
            required_headers = ["X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection"]
            missing_headers = [h for h in required_headers if h not in response.headers]
            
            if not missing_headers:
                self.log_result("Security Config", "Security Headers", "PASS", "All required security headers present")
            else:
                self.log_result("Security Config", "Security Headers", "VULNERABLE", 
                              f"Missing headers: {', '.join(missing_headers)}")
            
            # HSTS Check
            if "Strict-Transport-Security" not in response.headers:
                self.log_result("Security Config", "HSTS Header", "VULNERABLE", "HSTS header missing")
            else:
                self.log_result("Security Config", "HSTS Header", "PASS")
        except Exception as e:
            self.log_result("Security Config", "Security Headers", "ERROR", str(e))
        
        # Server Information Disclosure
        try:
            response = self.session.get(f"{self.base_url}/nonexistent")
            if "server" in response.headers and "uvicorn" in response.headers.get("server", "").lower():
                self.log_result("Security Config", "Server Version Disclosure", "LOW", "Server version exposed in headers")
            else:
                self.log_result("Security Config", "Server Version Disclosure", "PASS")
        except Exception as e:
            self.log_result("Security Config", "Server Version Disclosure", "ERROR", str(e))
    
    def test_sensitive_data_exposure(self):
        """Test Category 6: Sensitive Data Exposure"""
        print("\nTesting Sensitive Data Exposure...")
        
        # Check for exposed secrets in responses
        try:
            response = self.session.get(f"{self.base_url}/")
            sensitive_keywords = ["password", "secret", "key", "token", "database_url", "totp_secret"]
            found_sensitive = [kw for kw in sensitive_keywords if kw.lower() in response.text.lower()]
            
            if found_sensitive:
                self.log_result("Data Exposure", "Sensitive Data in Response", "VULNERABLE", 
                              f"Found: {', '.join(found_sensitive)}")
            else:
                self.log_result("Data Exposure", "Sensitive Data in Response", "PASS")
        except Exception as e:
            self.log_result("Data Exposure", "Sensitive Data in Response", "ERROR", str(e))
        
        # TOTP Secret Exposure Check (Critical)
        try:
            response = self.session.post(f"{self.base_url}/api/auth/register",
                json={"username": f"test_{int(time.time())}", "auth_salt": "test", "enc_salt": "test",
                      "auth_key": "test", "encrypted_mek": "test", "public_key": {}, "user_data_hmac": "test"})
            if "totp_secret" in response.text:
                self.log_result("Data Exposure", "TOTP Secret Exposure", "CRITICAL", 
                              "TOTP secret exposed in registration response!")
            else:
                self.log_result("Data Exposure", "TOTP Secret Exposure", "PASS", "TOTP secrets properly protected")
        except Exception as e:
            self.log_result("Data Exposure", "TOTP Secret Exposure", "ERROR", str(e))
    
    def test_file_upload_security(self):
        """Test Category 7: File Upload Security"""
        print("\nTesting File Upload Security...")
        
        # Malicious File Upload Tests
        malicious_files = [
            ("shell.php", b"<?php system($_GET['cmd']); ?>", "PHP web shell"),
            ("script.jsp", b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "JSP script"),
            ("malware.exe", b"MZ\x90\x00\x03\x00", "Windows executable"),
            ("../../../passwd", b"root:x:0:0:root:/root:/bin/bash", "Path traversal filename")
        ]
        
        for filename, content, description in malicious_files:
            try:
                files = {'file': (filename, content, 'application/octet-stream')}
                data = {
                    'filename_encrypted': base64.b64encode(filename.encode()).decode(),
                    'file_size_encrypted': base64.b64encode(str(len(content)).encode()).decode(),
                    'file_data_hmac': 'test_hmac'
                }
                
                response = self.session.post(f"{self.base_url}/api/files/upload", files=files, data=data, timeout=10)
                
                if response.status_code == 200:
                    self.log_result("File Upload", f"Malicious Upload ({description})", "VULNERABLE", 
                                  f"{filename} upload accepted")
                elif response.status_code in [400, 403, 415]:
                    self.log_result("File Upload", f"Malicious Upload ({description})", "PASS", 
                                  f"{filename} properly rejected")
                else:
                    self.log_result("File Upload", f"Malicious Upload ({description})", "INFO", 
                                  f"Status: {response.status_code}")
            except Exception as e:
                self.log_result("File Upload", f"Malicious Upload ({description})", "ERROR", str(e))
    
    def test_session_fixation(self):
        """Test Category 8: Session Security"""
        print("\nTesting Session Security...")
        
        # Session Fixation Test
        try:
            # Get initial session
            response1 = self.session.get(f"{self.base_url}/")
            initial_cookies = self.session.cookies.copy()
            
            # Attempt login
            response2 = self.session.post(f"{self.base_url}/api/auth/login",
                json={"username": "test", "auth_key": "test", "otp": "123456"})
            
            # Check if session changed
            final_cookies = self.session.cookies.copy()
            
            if len(initial_cookies) > 0 and initial_cookies == final_cookies:
                self.log_result("Session Security", "Session Fixation", "VULNERABLE", 
                              "Session ID not regenerated after login")
            else:
                self.log_result("Session Security", "Session Fixation", "PASS")
        except Exception as e:
            self.log_result("Session Security", "Session Fixation", "ERROR", str(e))
    
    def generate_report(self):
        """Generate concise security report"""
        print("\n" + "="*60)
        print("EPIC SERVER SECURITY ASSESSMENT REPORT")
        print("="*60)
        
        # Calculate statistics
        total_tests = len(self.results["tests"])
        passed = len([t for t in self.results["tests"] if t["status"] == "PASS"])
        vulnerable = len([t for t in self.results["tests"] if t["status"] == "VULNERABLE"])
        critical = len([t for t in self.results["tests"] if t["status"] == "CRITICAL"])
        low = len([t for t in self.results["tests"] if t["status"] == "LOW"])
        errors = len([t for t in self.results["tests"] if t["status"] == "ERROR"])
        
        # Summary
        print(f"SUMMARY:")
        print(f"   Total Tests: {total_tests}")
        print(f"   Passed: {passed}")
        print(f"   Vulnerable: {vulnerable}")
        print(f"   Critical: {critical}")
        print(f"   Low Risk: {low}")
        print(f"   Errors: {errors}")
        
        # Security Score
        if total_tests > 0:
            security_score = (passed / total_tests) * 100
            print(f"   Security Score: {security_score:.1f}%")
        
        # Risk Assessment
        if critical > 0:
            risk_level = "CRITICAL"
        elif vulnerable > 3:
            risk_level = "HIGH"
        elif vulnerable > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        print(f"   Risk Level: {risk_level}")
        
        # Critical Findings
        critical_findings = [t for t in self.results["tests"] if t["status"] in ["CRITICAL", "VULNERABLE"]]
        if critical_findings:
            print(f"\nCRITICAL FINDINGS:")
            for finding in critical_findings:
                print(f"   - {finding['category']}: {finding['test']}")
                if finding['details']:
                    print(f"     {finding['details']}")
        
        # Save detailed results
        self.results["summary"] = {
            "total_tests": total_tests,
            "passed": passed,
            "vulnerable": vulnerable,
            "critical": critical,
            "security_score": security_score if total_tests > 0 else 0,
            "risk_level": risk_level,
            "timestamp": time.time()
        }
        
        with open('security_test_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\nDetailed results saved to: security_test_results.json")
        print("="*60)

def main():
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "http://localhost:3010"
    
    print("Starting EPIC Server Security Assessment...")
    print(f"Target: {base_url}")
    print("WARNING: Only run against systems you own or have permission to test!")
    print("-" * 60)
    
    tester = SecurityTester(base_url)
    
    # Execute all security tests
    tester.test_input_validation()
    tester.test_authentication()
    tester.test_access_control()
    tester.test_injection()
    tester.test_security_configuration()
    tester.test_sensitive_data_exposure()
    tester.test_file_upload_security()
    tester.test_session_fixation()
    
    # Generate comprehensive report
    tester.generate_report()

if __name__ == "__main__":
    main() 