import requests
import argparse

PRESENCE_CHECKS = {
    "Strict-Transport-Security": {
        "severity": "High",
        "why": "Without this, connections can be downgraded to HTTP, allowing interception of traffic on untrusted networks",
        "recommended_header": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity": "High",
        "why": "Without this, injected scripts can run with no restriction from the browser",
        "recommended_header": "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        # header note: this header will break sites that use external scripts also base-uri 'none' may break pages that use the <base> tag
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "why": "Without this, a site can be loaded inside a hidden iframe, enabling clickjacking attacks",
        "recommended_header": "X-Frame-Options: DENY",
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "why": "Without this, browsers may guess a file's type instead of trusting the declared one, which can cause uploaded content to be run as a script",
        "recommended_header": "X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "why": "Without this, full URLs that may contain sensitive data can leak to external sites via the Referer header",
        "recommended_header": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "why": "Without this, embedded malicious content may access sensitive browser inputs like camera or location",
        "recommended_header": "Permissions-Policy: camera=(), microphone=(), geolocation=()"
    }
}

def check_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def fetch_headers(url):
    try:
        response = requests.get(url, timeout=10)
        return response
    except requests.exceptions.Timeout:
        print("Request timed out")
    except requests.exceptions.SSLError:
        print("SSL certificate error")
    except requests.exceptions.ConnectionError:
        print("Could not connect to the target server")
    except requests.exceptions.RequestException as e:
        print("Request error: ", e)
    return None

def check_headers_presence(headers):
    results = {}
    for header, info in PRESENCE_CHECKS.items():
        if header in headers:
            results[header] = (True, info)
        else:
            results[header] = (False, info)
    return results

def check_header_values(headers):
    results = []

    if "Strict-Transport-Security" in headers:
        value = headers["Strict-Transport-Security"]
        for part in value.split(";"):
            part = part.strip()
            if part.lower().startswith("max-age="):
                number = part[len("max-age="):]
                if number.isdigit() and int(number) < 15552000:
                    results.append(("High","Strict-Transport-Security","max-age is only " + number + " seconds (commonly recommended minimum is 15552000, about 6 months)"))

    if "Content-Security-Policy" in headers:
        value = headers["Content-Security-Policy"]
        for part in value.split(";"):
            words = part.split()
            if len(words) == 0:
                continue
            directive_name = words[0].lower()

            if "'unsafe-inline'" in words:
                if directive_name == "script-src":
                    results.append(("High", "Content-Security-Policy", "script-src allows 'unsafe-inline', so injected scripts can run"))
                elif directive_name == "default-src":
                    results.append(("High", "Content-Security-Policy", "default-src allows 'unsafe-inline', which can let injected scripts run unless script-src overrides it"))
                elif directive_name == "style-src":
                    results.append(("Low", "Content-Security-Policy", "style-src allows 'unsafe-inline' (inline styles are a lower risk than scripts)"))

            if "'unsafe-eval'" in words and directive_name in ("script-src", "default-src"):
                results.append(("High", "Content-Security-Policy", directive_name + " allows 'unsafe-eval', so text can be turned into runnable code"))




    return results

def print_value_results(results):
    print("\nHeaders present but weakly configured:\n")
    if len(results) == 0:
        print("None")
    else:
        for severity,header,reason in results:
            print("Header: " + header)
            print("Severity: " + severity)
            print("Reason: " + reason+"\n")




def print_results(results):
    print("\nAre important security headers present?\n")
    for header, (presence, info) in results.items():
        if not presence:
            print("[" + info["severity"] + "] " + header + " is NOT present")
            print("    Risk: " + info["why"])
            print("    Recommended: " + info["recommended_header"])
            print()
    present_count = 0
    for header, (presence, info) in results.items():
        if presence:
            present_count += 1
    print(str(present_count) + "/" + str(len(results)) + " security headers present")

parser = argparse.ArgumentParser(description="Checks security headers")
parser.add_argument("url", help="The URL to be checked")
args = parser.parse_args()

url = check_url(args.url)
response = fetch_headers(url)

if response is not None:
    presence_results = check_headers_presence(response.headers)
    print_results(presence_results)


    value_results = check_header_values(response.headers)
    print_value_results(value_results)

