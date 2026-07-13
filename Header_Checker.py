import requests
import argparse

def check_headers(url):
    headersAndRisks = {
        "Strict-Transport-Security": "Without this, connections can be downgraded to HTTP, allowing interception of traffic on untrusted networks",
        "X-Frame-Options": "Without this, the site can be loaded inside a hidden iframe, enabling clickjacking attacks",
        "X-Content-Type-Options": "Without \"nosniff\", browsers may change file types, potentially allowing scripts to run from untrusted content",
        "Content-Security-Policy": "Without this, injected scripts can run with no restriction from the browser",
        "Referrer-Policy": "Without this, full URLs with, potentially sensitive data, may leak to external sites via the Referer header",
        "Permissions-Policy": "Without this, embedded malicious content may access sensitive browser inputs like camera or location",
    }
    dictForHeaders = {}

    response = requests.get(url)

    if len(headersAndRisks) == len(headersAndRisks):
        for header,risk in headersAndRisks.items():
            if header in response.headers:
                dictForHeaders[header] = (True,risk)
            else:
                dictForHeaders[header] = (False, risk)
    return dictForHeaders

def print_results(results):
    print("\nAre important security headers present in metadata sent from the provided URL?\n")
    for [header,(presence,risk)] in results.items():
        if not presence:
            print(header +" is NOT present | RISK: " + risk)

parser = argparse.ArgumentParser(description="Checks security headers")
parser.add_argument("url", help="The URL to be checked")
args = parser.parse_args()

dictForHeaders = check_headers(args.url)
print_results(dictForHeaders)


