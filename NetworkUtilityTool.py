from scapy.all import ARP, Ether, srp
import requests
from bs4 import BeautifulSoup


def scan_network(ip_range):
    """
    Perform an ARP scan to discover devices on a network.
    """
    try:
        print(f"\n[INFO] Scanning network: {ip_range}")
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        answered, unanswered = srp(arp_request_broadcast, timeout=2, verbose=False)

        devices = []
        for sent, received in answered:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})
        return devices
    except PermissionError:
        print("[ERROR] Permission denied. Please run the program as an administrator/root.")
        return []
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred during the network scan: {e}")
        return []


def display_network_results(devices):
    """
    Display devices discovered on the network.
    """
    if devices:
        print("\n[INFO] Discovered Devices:")
        for device in devices:
            print(f" - IP: {device['ip']}, MAC: {device['mac']}")
    else:
        print("\n[INFO] No devices found on this network. Are you on the correct subnet?")


def crawl_and_discover_forms(url):
    """
    Crawls a given URL to discover all forms on the page
    """
    try:
        print(f"\n[INFO] Crawling {url} for forms...")
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all("form")
        print(f"[INFO] Found {len(forms)} form(s) on {url}.")
        return forms
    except requests.exceptions.MissingSchema:
        print("[ERROR] Invalid URL schema. Ensure you include 'http://' or 'https://' in the URL.")
        return []
    except requests.RequestException as e:
        print(f"[ERROR] Could not connect to {url}. Error: {e}")
        return []
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
        return []


def display_forms(forms):
    """
    Display discovered forms on a website.
    """
    if forms:
        print("\n[INFO] Discovered Forms Info:")
        for form in forms:
            action = form.attrs.get("action", "N/A")
            method = form.attrs.get("method", "GET").upper()
            print(f" - Form Action: {action}, Method: {method}")
    else:
        print("[INFO] No forms found on the website.")


def main_menu():
    """
    Main menu prompting the user to select a type of scan.
    """
    print("\nWhat would you like to do?")
    print("1. Scan a network range for devices.")
    print("2. Scan a website for forms.")
    print("Press Enter to quit.")


def main():
    while True:
        main_menu()
        choice = input("Enter your choice (1 or 2): ").strip()

        if not choice:
            print("[INFO] Exiting...")
            break

        if choice == "1":
            ip_range = input("Enter the network IP range to scan (e.g., 192.168.1.0/24): ").strip()
            if not ip_range:
                print("[ERROR] No IP range entered. Returning to menu.")
                continue

            devices = scan_network(ip_range)
            display_network_results(devices)

        elif choice == "2":
            url = input("Enter the URL of the website to scan (e.g., http://example.com): ").strip()
            if not url:
                print("[ERROR] No URL entered. Returning to menu.")
                continue

            forms = crawl_and_discover_forms(url)
            display_forms(forms)

        else:
            print("[ERROR] Invalid choice. Please enter 1, 2, or press Enter to quit.")

    input("\nPress Enter to exit...")


if __name__ == "__main__":
    main()