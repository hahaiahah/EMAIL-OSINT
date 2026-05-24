#!/usr/bin/env python3
import argparse
import hashlib
import requests
import dns.resolver
import phonenumbers
from phonenumbers import geocoder, carrier, timezone, number_type
import sys

def check_email_breach(email):
    sha1 = hashlib.sha1(email.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": "OSINT-Tool-GitHub"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                if line.startswith(suffix):
                    return int(line.split(':')[1])
        return 0
    except Exception as e:
        print(f"[!] Breach check error: {e}", file=sys.stderr)
        return None

def get_mx_ip(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = sorted([(r.preference, str(r.exchange)) for r in answers])
        if mx_records:
            mx_host = mx_records[0][1]
            ip = dns.resolver.resolve(mx_host, 'A')[0]
            return str(ip)
    except Exception:
        pass
    return None

def geolocate_ip(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                return (f"{data.get('city')}, {data.get('regionName')}, "
                        f"{data.get('country')} - {data.get('isp')}")
        return "Location unavailable"
    except Exception as e:
        return f"Geolocation error: {e}"

def analyze_email(email):
    print(f"\n[+] Analyzing email: {email}\n")
    count = check_email_breach(email)
    if count is None:
        print("[!] Could not check breaches.")
    elif count > 0:
        print(f"[!] Found in {count} known data breaches (haveibeenpwned.com)")
    else:
        print("[+] No known breaches found.")
    domain = email.split('@')[-1]
    print(f"[+] Domain: {domain}")
    mx_ip = get_mx_ip(domain)
    if mx_ip:
        print(f"[+] Mail server IP: {mx_ip}")
        print(f"[+] Estimated mail server location: {geolocate_ip(mx_ip)}")
    else:
        print("[-] Could not resolve MX record.")

def analyze_phone(phone):
    print(f"\n[+] Analyzing phone: {phone}\n")
    if not phone.startswith('+'):
        print("[!] Please use international format (+123456789).")
        return
    try:
        parsed = phonenumbers.parse(phone, None)
        if not phonenumbers.is_valid_number(parsed):
            print("[!] Invalid number.")
            return
        print(f"[+] International format: {phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}")
        print(f"[+] Region: {geocoder.description_for_number(parsed, 'en')}")
        print(f"[+] Original carrier: {carrier.name_for_number(parsed, 'en')}")
        print(f"[+] Time zones: {', '.join(timezone.time_zones_for_number(parsed))}")
        print(f"[+] Valid: {phonenumbers.is_valid_number(parsed)}")
        print(f"[+] Number type: {phonenumbers.PhoneNumberType.to_string(number_type(parsed))}")
        print("[i] Real-time geolocation is not supported for privacy reasons.")
    except Exception as e:
        print(f"[!] Error: {e}")

def main():
    parser = argparse.ArgumentParser(description='OSINT Digital Asset Checker - GitHub Edition')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--email', help='Email address to investigate')
    group.add_argument('--phone', help='Phone number (+123...)')
    args = parser.parse_args()
    if args.email:
        analyze_email(args.email.strip())
    elif args.phone:
        analyze_phone(args.phone.strip())

if __name__ == "__main__":
    main()
