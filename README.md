# Security-header-checker
A command line tool used to see if a website has set important HTTP security headers and then explains the risk of not having this header.

## What it does
It sends a request to the provided URL and then inspects the headers for presence and alerts the user to any missing headers.

## Headers checked and their associated risk of being missing

| Header | Severity | Risk if missing |
|---|---|---|
| `Strict-Transport-Security` | High | Connections can be downgraded to unencrypted HTTP |
| `Content-Security-Policy` | High | Injected scripts can run unrestricted (XSS) |
| `X-Frame-Options` | Medium | Site can be loaded in a hidden iframe (clickjacking) |
| `X-Content-Type-Options` | Medium | Browsers may guess file types, risking script injection |
| `Referrer-Policy` | Low | Full URLs may leak to other sites via the Referer header |
| `Permissions-Policy` | Low | Embedded content may access camera, mic or location |

| Header | Risk |

| `Strict-Transport-Security` | Forces HTTPS, preventing downgrade to unencrypted HTTP |

| `X-Frame-Options` | Prevents the site being loaded in a hidden iframe (clickjacking) |

| `X-Content-Type-Options` | Stops browsers guessing file types, reducing script injection risk |

| `Content-Security-Policy` | Restricts which sources scripts/styles/etc. can load from, mitigating XSS |

| `Referrer-Policy` | Controls how much URL data leaks to other sites via the Referrer header |

| `Permissions-Policy` | Restricts access to browser features like camera, mic, and location |

## Usage
`python Header_Checker.py https://example.com`
Only use on websites you own or have permission to test

## Planned improvements 
- Add a more detailed analysis of `Content-Security-Policy`
- Add batch URL scanning from another file
- Create a "score" based on how secure the URL is
- JSON output option for scripting and automation
