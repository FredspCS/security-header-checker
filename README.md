# Security-header-checker
A command line tool used to see if a website has set important HTTP security headers and then explains the risk of not having this header.

# What it does
It sends a request to the provided URL and then inspects the headers for presence and alerts the user to any missing headers.

# Headers checked and their associated risk of being missing

| Header | Risk |
| `Strict-Transport-Security` | Forces HTTPS, preventing downgrade to unencrypted HTTP |
| `X-Frame-Options` | Prevents the site being loaded in a hidden iframe (clickjacking) |
| `X-Content-Type-Options` | Stops browsers guessing file types, reducing script injection risk |
| `Content-Security-Policy` | Restricts which sources scripts/styles/etc. can load from, mitigating XSS |
| `Referrer-Policy` | Controls how much URL data leaks to other sites via the Referrer header |
| `Permissions-Policy` | Restricts access to browser features like camera, mic, and location |

# Usage
python header_checker.py https://example.com

##Plan
