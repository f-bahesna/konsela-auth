# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **fbahezna@gmail.com**

Please include the following information:

1. Type of vulnerability
2. Full paths of source file(s) related to the vulnerability
3. Location of the affected source code (tag/branch/commit or direct URL)
4. Step-by-step instructions to reproduce the issue
5. Proof-of-concept or exploit code (if possible)
6. Impact of the vulnerability, including how an attacker might exploit it

### What to expect

- You will receive a response within 48 hours acknowledging receipt
- We will investigate and confirm the vulnerability
- We will develop a fix and release it as soon as possible
- We will publicly disclose the vulnerability after the fix is released
- We will credit you in the security advisory (unless you prefer to remain anonymous)

## Security Best Practices

When using this package:

1. **Never commit private keys to version control**
   - Add `*.pem` to `.gitignore`
   - Use environment variables for key paths

2. **Use strong key sizes**
   - Minimum 2048 bits for RSA
   - Recommended 4096 bits for production

3. **Protect private keys**
   - Set file permissions to 600
   - Store outside web root
   - Rotate keys periodically

4. **Use HTTPS only**
   - Never transmit tokens over HTTP
   - Configure HSTS headers

5. **Implement rate limiting**
   - Prevent brute force attacks
   - Configure appropriate thresholds

6. **Hash passwords properly**
   - Use Argon2ID or Bcrypt
   - Never use MD5, SHA1, or plain text

7. **Validate all inputs**
   - Use built-in validation
   - Sanitize user inputs

8. **Keep dependencies updated**
   - Regularly run `composer update`
   - Monitor for security advisories

9. **Implement token blacklisting**
   - For logout functionality
   - For compromised tokens

10. **Monitor and log**
    - Log failed authentication attempts
    - Monitor for suspicious patterns
    - Set up alerts for security events

## Known Security Considerations

### JWT Limitations

- JWTs cannot be invalidated before expiration (implement blacklisting)
- Tokens are self-contained (keep TTL short)
- Tokens can be decoded by anyone (never include sensitive data)

### Rate Limiting

- Configure rate limiting at both application and infrastructure levels
- Consider using Redis for distributed rate limiting

### Key Rotation

- Plan for key rotation strategy
- Implement graceful key rollover
- Keep old public keys for verification during transition

## Security Updates

Security updates will be released as soon as possible after a vulnerability is confirmed. Please ensure you are subscribed to notifications for this repository to receive security updates.

## Compliance

This package is designed to help with:

- OWASP Top 10 protection
- JWT best practices (RFC 7519)
- Password storage guidelines (NIST SP 800-63B)
- Input validation and sanitization

However, full compliance depends on proper implementation and configuration by the end user.

## Contact

For security concerns: fbahezna@gmail.com
For general issues: [GitHub Issues](https://github.com/konsela/auth/issues)
