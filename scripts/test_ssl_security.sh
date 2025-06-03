#!/bin/bash

echo "🔒 SSL/TLS Security Test Suite"
echo "=============================="

SERVER_URL="your-server:8000"

# Test 1: Check if HTTPS is enforced
echo "Test 1: HTTP to HTTPS redirect..."
HTTP_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://$SERVER_URL)
if [ "$HTTP_RESPONSE" = "307" ] || [ "$HTTP_RESPONSE" = "301" ]; then
    echo "✅ HTTP redirects to HTTPS"
else
    echo "❌ HTTP does not redirect to HTTPS (Response: $HTTP_RESPONSE)"
fi

# Test 2: Check security headers
echo "Test 2: Security headers..."
HEADERS=$(curl -s -I https://$SERVER_URL)

if echo "$HEADERS" | grep -q "Strict-Transport-Security"; then
    echo "✅ HSTS header present"
else
    echo "❌ HSTS header missing"
fi

if echo "$HEADERS" | grep -q "X-Content-Type-Options: nosniff"; then
    echo "✅ X-Content-Type-Options header present"
else
    echo "❌ X-Content-Type-Options header missing"
fi

# Test 3: Check TLS version
echo "Test 3: TLS version..."
TLS_VERSION=$(echo | openssl s_client -connect $SERVER_URL 2>/dev/null | grep "Protocol" | head -1)
echo "TLS Version: $TLS_VERSION"

# Test 4: Check certificate
echo "Test 4: Certificate validity..."
CERT_DATES=$(echo | openssl s_client -connect $SERVER_URL 2>/dev/null | openssl x509 -noout -dates)
echo "$CERT_DATES"

echo "=============================="
echo "🔒 SSL/TLS Security Test Complete" 