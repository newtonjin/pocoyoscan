import nmap
import psutil
import requests
import json
from bs4 import BeautifulSoup

VULNERABILITIES = {
    'wp-login': 'WordPress login page found',
    'xmlrpc.php': 'WordPress XML-RPC interface found',
    'readme.html': 'WordPress readme file found',
    'license.txt': 'WordPress license file found',
    'wp-config.php': 'WordPress configuration file found',
    'wp-content/uploads/': 'WordPress uploads directory found',
    'wp-includes/': 'WordPress includes directory found',
    'wp-admin/admin-ajax.php': 'WordPress AJAX API found',
    'wp-admin/admin-post.php': 'WordPress admin-post found',
    'wp-admin/admin-ajax.php?action=revslider_ajax_action': 'WordPress Revolution Slider plugin vulnerability found',
    'wp-admin/admin-ajax.php?action=wp_ada_compliance_basic_scan': 'WordPress WP ADA Compliance Check Basic plugin vulnerability found',
    'wp-admin/admin-ajax.php?action=ajax_quick_search': 'WordPress WP Fastest Cache plugin vulnerability found',
    'wp-admin/admin-ajax.php?action=revslider_show_image': 'WordPress Showbiz Pro plugin vulnerability found',
    'wp-admin/admin-ajax.php?action=wp_woocommerce_ajax_get_product_thumbnail': 'WordPress WooCommerce plugin vulnerability found',
    'wp-content/plugins/woocommerce/includes/class-wc-cart.php': 'WordPress WooCommerce plugin vulnerability found',
    'wp-content/plugins/woocommerce/includes/class-wc-checkout.php': 'WordPress WooCommerce plugin vulnerability found',
    'wp-content/plugins/woocommerce/includes/class-wc-customer.php': 'WordPress WooCommerce plugin vulnerability found',
    'wp-content/plugins/woocommerce/includes/class-wc-order.php': 'WordPress WooCommerce plugin vulnerability found',
    'wp-content/plugins/woocommerce/includes/class-wc-product-variable.php': 'WordPress WooCommerce plugin vulnerability found',
    'wp-content/plugins/woocommerce/includes/class-wc-shipping.php': 'WordPress WooCommerce plugin vulnerability found',
    'wp-content/plugins/woocommerce/includes/class-wc-webhook.php': 'WordPress WooCommerce plugin vulnerability found'
}

def scan_for_exploits():
    nm = nmap.PortScanner()

    host = input("Enter the host IP address: ")
    try:
        nm.scan(host, arguments='-sV')
    except Exception as e:
        print(f"Error: {e}")
        return

    for port in nm[host]['tcp']:
        service = nm[host]['tcp'][port]['name']
        version = nm[host]['tcp'][port]['version']
        print(f"Port {port} - {service} {version}")

        # Show exploits for the service version
        url = f"https://www.exploit-db.com/search?cve=&platform=&port={port}&type=&vendor=&version={version}"
        print(f"Exploits for {service} {version}: {url}")
        
        # Check for vulnerabilities using Nmap NSE scripts
        if service == 'http' or service == 'https':
            try:
                nse_script_output = nm.scan(hosts=host, ports=str(port), arguments=f"--script http-vuln-*")
                if 'http-vuln-' in nse_script_output:
                    print(f"Nmap NSE scripts found the following vulnerabilities for {service} {version}:")
                    for line in nse_script_output['scan'][host]['tcp'][port]['script'].split('\n'):
                        if 'http-vuln-' in line:
                            print(line.strip())
                else:
                    print(f"No vulnerabilities found for {service} {version}")
            except Exception as e:
                print(f"Error: {e}")

def show_hosts():
    nm = nmap.PortScanner()

    # Scan all hosts in the local network
    nm.scan(hosts='192.168.1.0/24', arguments='-n -sP')

    # Print all the hosts that are up
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            print(f"Host {host} is up")

def check_cves(version):
    version_without_dots = version.replace('.', '')
    url = f"https://www.cvedetails.com/version-search.php?vendor=Wordpress&product=Wordpress&version={version}"
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    cves = soup.select('table.listtable tr td a[href^="/cve/CVE-"]')
    if len(cves) > 0:
        print(f"WordPress {version} has the following CVEs:")
        for cve in cves:
            print(cve.text)
    else:
        print(f"No CVEs found for WordPress version {version}")

def wordpress_scan():
    global url 
    url = input("Enter the WordPress site URL: ")
    if not url.startswith('http'):
        url = 'http://' + url
    try:
        response = requests.get(url)
    except Exception as e:
        print(f"Error: {e}")
        return

    soup = BeautifulSoup(response.content, 'html.parser')
    version = soup.find('meta', attrs={'name': 'generator'})
    
    form = soup.find('form', attrs={'enctype': 'multipart/form-data'})
    if form:
        print("File upload form found")

        # Check if the file upload form allows PHP files
        input_field = form.find('input', attrs={'type': 'file'})
        if input_field:
            accept = input_field.get('accept')
            if accept and 'php' in accept:
                print("File upload form allows PHP files")
            else:
                print("File upload form does not allow PHP files")
        else:
            print("File upload input field not found")
    else:
        print("File upload form not found")
        
    if version:
        version = version['content']
        print(f"WordPress version: {version}")
        check_cves(version)

        # Check for vulnerabilities using Nmap NSE scripts
        try:
            nse_script_output = nmap.PortScanner().scan(urlparse(url).hostname, arguments=f"-p 80,443 --script http-vuln-*")
            if 'http-vuln-' in nse_script_output:
                print(f"Nmap NSE scripts found the following vulnerabilities for WordPress version {version}:")
                for line in nse_script_output.split('\n'):
                    if 'http-vuln-' in line:
                        print(line.strip())
            else:
                print(f"No vulnerabilities found for WordPress version {version}")
        except Exception as e:
            print(f"Error: {e}")

        # Check for common vulnerabilities
        check_vulnerabilities(response.text)

        # Check for vulnerabilities using WPScan
        try:
            version_without_dots = version.replace('.', '')
            version_without_dots = version_without_dots.replace('WordPress ','')
            wpscan_url = f"https://wpscan.com/api/v3/wordpresses/{version_without_dots}"
            headers = {'Authorization': f"Token token={WPSCAN_API_TOKEN}",'Content-Type':'application/json'}
            response = requests.get(wpscan_url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                if data is not None:
                    print(f"WPScan found the following vulnerabilities for Wordpress version {version} in the url {url}")
                    formatted_data = json.dumps(data, indent=4)
                    print(formatted_data)
                else:
                    print(f"No information found for WordPress version {version}")
            else:
                print(f"WPScan API returned status code {response.status_code}")
        except Exception as e:
            print(f"WPScan API key wasn't set")
    else:
        print("WordPress version not found")
        
        
        
def check_vulnerabilities(response_text):
    for vulnerability, description in VULNERABILITIES.items():
        if vulnerability in response_text:
            print(f"{url}/{vulnerability}    - {description}")
        
while True:
    print("""


 ██▓███  ▒█████  ▄████▄  ▒█████▓██   ██▓▒█████       ██████ ▄████▄  ▄▄▄      ███▄    █ ███▄    █▓█████ ██▀███  
▓██░  ██▒██▒  ██▒██▀ ▀█ ▒██▒  ██▒██  ██▒██▒  ██▒   ▒██    ▒▒██▀ ▀█ ▒████▄    ██ ▀█   █ ██ ▀█   █▓█   ▀▓██ ▒ ██▒
▓██░ ██▓▒██░  ██▒▓█    ▄▒██░  ██▒▒██ ██▒██░  ██▒   ░ ▓██▄  ▒▓█    ▄▒██  ▀█▄ ▓██  ▀█ ██▓██  ▀█ ██▒███  ▓██ ░▄█ ▒
▒██▄█▓▒ ▒██   ██▒▓▓▄ ▄██▒██   ██░░ ▐██▓▒██   ██░     ▒   ██▒▓▓▄ ▄██░██▄▄▄▄██▓██▒  ▐▌██▓██▒  ▐▌██▒▓█  ▄▒██▀▀█▄  
▒██▒ ░  ░ ████▓▒▒ ▓███▀ ░ ████▓▒░░ ██▒▓░ ████▓▒░   ▒██████▒▒ ▓███▀ ░▓█   ▓██▒██░   ▓██▒██░   ▓██░▒████░██▓ ▒██▒
▒▓▒░ ░  ░ ▒░▒░▒░░ ░▒ ▒  ░ ▒░▒░▒░  ██▒▒▒░ ▒░▒░▒░    ▒ ▒▓▒ ▒ ░ ░▒ ▒  ░▒▒   ▓▒█░ ▒░   ▒ ▒░ ▒░   ▒ ▒░░ ▒░ ░ ▒▓ ░▒▓░
░▒ ░      ░ ▒ ▒░  ░  ▒    ░ ▒ ▒░▓██ ░▒░  ░ ▒ ▒░    ░ ░▒  ░ ░ ░  ▒    ▒   ▒▒ ░ ░░   ░ ▒░ ░░   ░ ▒░░ ░  ░ ░▒ ░ ▒░
░░      ░ ░ ░ ▒ ░       ░ ░ ░ ▒ ▒ ▒ ░░ ░ ░ ░ ▒     ░  ░  ░ ░         ░   ▒     ░   ░ ░   ░   ░ ░   ░    ░░   ░ 
            ░ ░ ░ ░         ░ ░ ░ ░        ░ ░           ░ ░ ░           ░  ░        ░         ░   ░  ░  ░     
                ░               ░ ░                        ░                                                   
  by: Newtonj1n""")
    print("1. Scan for exploits")
    print("2. Show all hosts alive in the local network")
    print("3. WordPress scan")
    print("4. Show all the remote TCP connections")
    print("7. Set WPScan API token")
    print("8. Exit")

    choice = input("Enter your choice: ")

    if choice == "1":
        scan_for_exploits()
    elif choice == "2":
        show_hosts()
    elif choice == "3":
        wordpress_scan()
    elif choice == "4":
        connections = psutil.net_connections(kind='tcp')

        # Print all the remote TCP connections
        for conn in connections:
            if conn.status == 'ESTABLISHED':
                print(f"Local address: {conn.laddr.ip}:{conn.laddr.port} - Remote address: {conn.raddr.ip}:{conn.raddr.port}")
    elif choice == "7":
        WPSCAN_API_TOKEN = input("Enter your WPScan API token: ")
    elif choice == "8":
        break
    else:
        print("Invalid choice. Please try again.")