#!/usr/bin/env python3
"""
EPIC Server Penetration Testing Suite
Comprehensive security testing for all vulnerability categories
"""

import requests
import json
import time
import base64
import os
import sys
from typing import Dict, List, Optional
import hashlib
import hmac
from urllib.parse import urljoin

class SecurityTester:
    def __init__(self, base_url: str = "http://localhost:3010"):
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = []
        
    def log_test(self, test_id: str, description: str, result: str, severity: str = "INFO"):
        """Log test results"""
        self.test_results.append({
            "test_id": test_id,
            "description": description,
            "result": result,
            "severity": severity,
            "timestamp": time.time()
        })
        print(f"[{severity}] {test_id}: {description} - {result}")
    
    def test_input_validation(self):
        """Test cases for improper input validation"""
        print("\nTesting Input Validation...")
        
        # TC-IV-001: SQL Injection in username
        malicious_usernames = [
            "admin'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin' UNION SELECT * FROM users --"
        ]
        
        for username in malicious_usernames:
            try:
                response = self.session.post(
                    f"{self.base_url}/api/user/{username}/salts",
                    timeout=5
                )
                if response.status_code == 500:
                    self.log_test("TC-IV-001", f"SQL injection test with {username}", "VULNERABLE - 500 error", "HIGH")
                else:
                    self.log_test("TC-IV-001", f"SQL injection test with {username}", "PASS - Proper handling", "PASS")
            except Exception as e:
                self.log_test("TC-IV-001", f"SQL injection test with {username}", f"ERROR: {str(e)}", "ERROR")
        
        # TC-IV-002: XSS in input fields
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>"
        ]
        
        for payload in xss_payloads:
            try:
                response = self.session.post(
                    f"{self.base_url}/api/auth/register",
                    json={
                        "username": payload,
                        "auth_salt": "test",
                        "enc_salt": "test", 
                        "auth_key": "test",
                        "encrypted_mek": "test",
                        "public_key": {"test": "data"},
                        "user_data_hmac": "test"
                    },
                    timeout=5
                )
                if payload in response.text:
                    self.log_test("TC-IV-002", f"XSS test with {payload}", "VULNERABLE - Reflected XSS", "HIGH")
                else:
                    self.log_test("TC-IV-002", f"XSS test with {payload}", "PASS - Input sanitized", "PASS")
            except Exception as e:
                self.log_test("TC-IV-002", f"XSS test with {payload}", f"ERROR: {str(e)}", "ERROR")
    
    def test_authentication(self):
        """Test cases for broken authentication"""
        print("\nTesting Authentication Security...")
        
        # TC-BA-001: Weak password policy
        weak_passwords = ["123", "password", "admin", "test"]
        
        for pwd in weak_passwords:
            try:
                response = self.session.post(
                    f"{self.base_url}/api/auth/register",
                    json={
                        "username": f"testuser_{int(time.time())}",
                        "password": pwd,  # This should be rejected
                        "auth_salt": "test",
                        "enc_salt": "test",
                        "auth_key": "test", 
                        "encrypted_mek": "test",
                        "public_key": {"test": "data"},
                        "user_data_hmac": "test"
                    },
                    timeout=5
                )
                if response.status_code == 200:
                    self.log_test("TC-BA-001", f"Weak password test: {pwd}", "VULNERABLE - Weak password accepted", "MEDIUM")
                else:
                    self.log_test("TC-BA-001", f"Weak password test: {pwd}", "PASS - Weak password rejected", "PASS")
            except Exception as e:
                self.log_test("TC-BA-001", f"Weak password test: {pwd}", f"ERROR: {str(e)}", "ERROR")
        
        # TC-BA-002: Rate limiting test
        print("Testing rate limiting...")
        failed_attempts = 0
        for i in range(10):
            try:
                response = self.session.post(
                    f"{self.base_url}/api/auth/login",
                    json={
                        "username": "nonexistent_user",
                        "auth_key": "wrong_key",
                        "otp": "000000"
                    },
                    timeout=5
                )
                if response.status_code == 429:
                    self.log_test("TC-BA-002", f"Rate limiting after {i+1} attempts", "PASS - Rate limited", "PASS")
                    break
                failed_attempts += 1
                time.sleep(0.1)  # Small delay between attempts
            except Exception as e:
                self.log_test("TC-BA-002", f"Rate limiting test attempt {i+1}", f"ERROR: {str(e)}", "ERROR")
                break
        
        if failed_attempts >= 10:
            self.log_test("TC-BA-002", "Rate limiting test", "VULNERABLE - No rate limiting", "HIGH")
    
    def test_access_control(self):
        """Test cases for broken access control"""
        print("\nTesting Access Control...")
        
        # TC-AC-001: Test unauthorized access to files endpoint
        try:
            response = self.session.get(f"{self.base_url}/api/files/", timeout=5)
            if response.status_code == 200:
                self.log_test("TC-AC-001", "Unauthorized file access", "VULNERABLE - No authentication required", "HIGH")
            elif response.status_code == 401:
                self.log_test("TC-AC-001", "Unauthorized file access", "PASS - Authentication required", "PASS")
            else:
                self.log_test("TC-AC-001", "Unauthorized file access", f"UNEXPECTED - Status {response.status_code}", "MEDIUM")
        except Exception as e:
            self.log_test("TC-AC-001", "Unauthorized file access", f"ERROR: {str(e)}", "ERROR")
        
        # TC-AC-002: Test direct object reference
        test_file_ids = [
            "00000000-0000-0000-0000-000000000001",
            "11111111-1111-1111-1111-111111111111",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        ]
        
        for file_id in test_file_ids:
            try:
                response = self.session.get(f"{self.base_url}/api/files/{file_id}/metadata", timeout=5)
                if response.status_code == 200:
                    self.log_test("TC-AC-002", f"Direct object reference: {file_id}", "VULNERABLE - Unauthorized access", "HIGH")
                elif response.status_code in [401, 403]:
                    self.log_test("TC-AC-002", f"Direct object reference: {file_id}", "PASS - Access denied", "PASS")
                else:
                    self.log_test("TC-AC-002", f"Direct object reference: {file_id}", f"Status {response.status_code}", "INFO")
            except Exception as e:
                self.log_test("TC-AC-002", f"Direct object reference: {file_id}", f"ERROR: {str(e)}", "ERROR")
    
    def test_injection(self):
        """Test cases for injection vulnerabilities"""
        print("\nTesting Injection Vulnerabilities...")
        
        # TC-IN-001: Command injection
        command_payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "&& whoami",
            "$(cat /etc/passwd)"
        ]
        
        for payload in command_payloads:
            try:
                # Test in username field
                response = self.session.get(f"{self.base_url}/api/user/{payload}/salts", timeout=5)
                if "root:" in response.text or "bin:" in response.text:
                    self.log_test("TC-IN-001", f"Command injection: {payload}", "VULNERABLE - Command executed", "HIGH")
                else:
                    self.log_test("TC-IN-001", f"Command injection: {payload}", "PASS - Command not executed", "PASS")
            except Exception as e:
                self.log_test("TC-IN-001", f"Command injection: {payload}", f"ERROR: {str(e)}", "ERROR")
    
    def test_security_misconfiguration(self):
        """Test cases for security misconfiguration"""
        print("\nTesting Security Configuration...")
        
        # TC-SM-001: Security headers check
        try:
            response = self.session.get(f"{self.base_url}/", timeout=5)
            headers = response.headers
            
            required_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options", 
                "X-XSS-Protection",
                "Content-Security-Policy"
            ]
            
            missing_headers = []
            for header in required_headers:
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                self.log_test("TC-SM-001", f"Security headers check", f"VULNERABLE - Missing: {', '.join(missing_headers)}", "MEDIUM")
            else:
                self.log_test("TC-SM-001", "Security headers check", "PASS - All security headers present", "PASS")
                
        except Exception as e:
            self.log_test("TC-SM-001", "Security headers check", f"ERROR: {str(e)}", "ERROR")
        
        # TC-SM-002: Error message information disclosure
        try:
            response = self.session.get(f"{self.base_url}/api/nonexistent", timeout=5)
            if "Traceback" in response.text or "File \"" in response.text:
                self.log_test("TC-SM-002", "Error message disclosure", "VULNERABLE - Stack trace exposed", "HIGH")
            else:
                self.log_test("TC-SM-002", "Error message disclosure", "PASS - Generic error messages", "PASS")
        except Exception as e:
            self.log_test("TC-SM-002", "Error message disclosure", f"ERROR: {str(e)}", "ERROR")
    
    def test_sensitive_data_exposure(self):
        """Test cases for sensitive data exposure"""
        print("\nTesting Sensitive Data Exposure...")
        
        # TC-SDE-001: Check for credentials in responses
        try:
            response = self.session.get(f"{self.base_url}/", timeout=5)
            sensitive_patterns = [
                "password", "secret", "key", "token", "credential",
                "DATABASE_URL", "SECRET_KEY", "TOTP_ENCRYPTION_KEY"
            ]
            
            found_sensitive = []
            response_text = response.text.lower()
            for pattern in sensitive_patterns:
                if pattern.lower() in response_text:
                    found_sensitive.append(pattern)
            
            if found_sensitive:
                self.log_test("TC-SDE-001", "Sensitive data in response", f"VULNERABLE - Found: {', '.join(found_sensitive)}", "HIGH")
            else:
                self.log_test("TC-SDE-001", "Sensitive data in response", "PASS - No sensitive data exposed", "PASS")
                
        except Exception as e:
            self.log_test("TC-SDE-001", "Sensitive data in response", f"ERROR: {str(e)}", "ERROR")
    
    def test_file_upload_security(self):
        """Test file upload security"""
        print("\nTesting File Upload Security...")
        
        # TC-FU-001: Malicious file upload
        malicious_files = [
            ("malware.exe", b"MZ\x90\x00"),  # PE header
            ("script.php", b"<?php system($_GET['cmd']); ?>"),
            ("shell.jsp", b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>")
        ]
        
        for filename, content in malicious_files:
            try:
                files = {'file': (filename, content, 'application/octet-stream')}
                data = {
                    'filename_encrypted': base64.b64encode(filename.encode()).decode(),
                    'file_size_encrypted': base64.b64encode(str(len(content)).encode()).decode(),
                    'file_data_hmac': 'test_hmac'
                }
                
                response = self.session.post(
                    f"{self.base_url}/api/files/upload",
                    files=files,
                    data=data,
                    timeout=10
                )
                
                if response.status_code == 200:
                    self.log_test("TC-FU-001", f"Malicious file upload: {filename}", "VULNERABLE - File accepted", "HIGH")
                elif response.status_code in [400, 403]:
                    self.log_test("TC-FU-001", f"Malicious file upload: {filename}", "PASS - File rejected", "PASS")
                else:
                    self.log_test("TC-FU-001", f"Malicious file upload: {filename}", f"Status {response.status_code}", "INFO")
                    
            except Exception as e:
                self.log_test("TC-FU-001", f"Malicious file upload: {filename}", f"ERROR: {str(e)}", "ERROR")
    
    def generate_report(self):
        """Generate a summary report"""
        print("\n" + "="*60)
        print("PENETRATION TESTING SUMMARY REPORT")
        print("="*60)
        
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r['result'].startswith('PASS')])
        vulnerable_tests = len([r for r in self.test_results if 'VULNERABLE' in r['result']])
        error_tests = len([r for r in self.test_results if r['severity'] == 'ERROR'])
        
        print(f"Total Tests Executed: {total_tests}")
        print(f"Tests Passed: {passed_tests}")
        print(f"Vulnerabilities Found: {vulnerable_tests}")
        print(f"Test Errors: {error_tests}")
        
        if vulnerable_tests > 0:
            print(f"\nVULNERABILITIES DETECTED:")
            for result in self.test_results:
                if 'VULNERABLE' in result['result']:
                    print(f"  - {result['test_id']}: {result['description']} - {result['result']}")
        
        print(f"\nSecurity Score: {(passed_tests/total_tests)*100:.1f}%")
        
        if vulnerable_tests == 0:
            print("Overall Status: SECURE")
        elif vulnerable_tests <= 2:
            print("Overall Status: NEEDS ATTENTION")
        else:
            print("Overall Status: HIGH RISK")
        
        # Save detailed report
        with open('penetration_test_results.json', 'w') as f:
            json.dump(self.test_results, f, indent=2)
        print(f"\nDetailed results saved to: penetration_test_results.json")

def main():
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = "http://localhost:3010"
    
    print(f"Starting penetration testing against: {base_url}")
    print("WARNING: Only run this against systems you own or have permission to test!")
    
    tester = SecurityTester(base_url)
    
    # Run all test categories
    tester.test_input_validation()
    tester.test_authentication()
    tester.test_access_control()
    tester.test_injection()
    tester.test_security_misconfiguration()
    tester.test_sensitive_data_exposure()
    tester.test_file_upload_security()
    
    # Generate final report
    tester.generate_report()

if __name__ == "__main__":
    main() 