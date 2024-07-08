import sys
import argparse
import requests
import time
import logging
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from PIL import Image, ImageSequence

# Base URL for querying crt.sh
BASE_URL = "https://crt.sh/?q={}&output=json"

class Colors:
    RED = "\33[91m"
    BLUE = "\33[94m"
    GREEN = "\33[92m"
    RESET = "\033[0m"

def print_colored(text, color, end="\n", delay=0.0):
    """Prints text in a given color with an optional delay between each character."""
    for char in text:
        print(color + char + Colors.RESET, end="", flush=True)
        time.sleep(delay)
    print(end=end)

def parser_error(errmsg):
    """Print usage information and error message, then exit the script."""
    print(f"Usage: python3 {sys.argv[0]} [Options] use -h for help")
    print(f"Error: {errmsg}")
    sys.exit()

def parse_args():
    """Parse command-line arguments using argparse."""
    parser = argparse.ArgumentParser(
        description="Fetch subdomains from crt.sh",
        epilog='Example:\r\npython3 script.py -d google.com'
    )
    parser.error = parser_error
    parser.add_argument('-d', '--domain', help='Target domain to fetch subdomains from', required=True)
    parser.add_argument('-r', '--recursive', help='Enable recursive search for subdomains', action='store_true')
    parser.add_argument('-w', '--wildcard', help='Include wildcard subdomains in output', action='store_true')
    parser.add_argument('-o', '--output', help='Output file to save subdomains', type=str)
    parser.add_argument('-v', '--verbose', help='Enable verbose output', action='store_true')
    parser.add_argument('-e', '--exclude-wildcards', help='Exclude wildcard subdomains', action='store_true')
    parser.add_argument('--user-agent', help='Custom User-Agent for requests', type=str, default='Mozilla/5.0')
    parser.add_argument('--rate-limit', help='Delay between requests in seconds', type=float, default=0.0)
    parser.add_argument('--timeout', help='Timeout for requests in seconds', type=float, default=25.0)
    parser.add_argument('--log', help='Log file to save logs', type=str, default='script.log')
    
    # New arguments for enhanced features
    parser.add_argument('-x', '--extensions', help='Filter by domain extensions (comma-separated)', type=str)
    parser.add_argument('-f', '--format', help='Output format (csv, json, etc.)', type=str, choices=['csv', 'json'])
    parser.add_argument('-i', '--interactive', help='Enable interactive mode', action='store_true')
    parser.add_argument('-t', '--technique', help='Subdomain enumeration technique', choices=['crtsh', 'dns', 'bruteforce'], default='crtsh')

    return parser.parse_args()

def setup_logging(log_file, verbose):
    """Set up logging configuration."""
    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG if verbose else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

def requests_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504)):
    """Create a requests session with retry logic."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def fetch_subdomains(domain, user_agent, timeout, verbose, rate_limit):
    """Fetch subdomains from crt.sh for a given domain."""
    session = requests_retry_session()
    headers = {'User-Agent': user_agent}
    try:
        response = session.get(BASE_URL.format(domain), headers=headers, timeout=timeout)
        response.raise_for_status()  # Raise an exception for HTTP errors
        if verbose:
            logging.info(f"Fetched data for {domain}")
        time.sleep(rate_limit)  # Rate limiting
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Error fetching data from CRT.SH: {e}")
        return []

def process_subdomains(domain, recursive, wildcard, exclude_wildcards, verbose, user_agent, timeout, rate_limit, extensions=None):
    """Process fetched subdomains and return a set of unique subdomains."""
    subdomains = set()
    wildcard_subdomains = set()

    def add_subdomain(subdomain):
        """Add subdomain to the appropriate set based on the presence of a wildcard."""
        if '*' in subdomain:
            wildcard_subdomains.add(subdomain)
        else:
            subdomains.add(subdomain)

    # Fetch subdomains for the main domain
    jsondata = fetch_subdomains(domain, user_agent, timeout, verbose, rate_limit)
    if not jsondata:
        return subdomains

    # Process each entry in the fetched JSON data
    for entry in jsondata:
        name_value = entry.get('name_value', '')
        subnames = name_value.splitlines()
        for subname in subnames:
            add_subdomain(subname.strip())

    # If recursive flag is set, fetch subdomains for each wildcard subdomain
    if recursive:
        for wildcard_subdomain in list(wildcard_subdomains):
            wildcard_subdomain_encoded = wildcard_subdomain.replace('*', '%25')
            jsondata_recursive = fetch_subdomains(wildcard_subdomain_encoded, user_agent, timeout, verbose, rate_limit)
            if not jsondata_recursive:
                continue

            for entry in jsondata_recursive:
                name_value = entry.get('name_value', '')
                subnames = name_value.splitlines()
                for subname in subnames:
                    add_subdomain(subname.strip())

    # If wildcard flag is set, include wildcard subdomains in the final set
    if wildcard:
        subdomains.update(wildcard_subdomains)

    # If exclude wildcards flag is set, remove wildcard subdomains from the final set
    if exclude_wildcards:
        subdomains.difference_update(wildcard_subdomains)

    # Filter subdomains by domain extensions if provided
    if extensions:
        filtered_subdomains = set()
        for subdomain in subdomains:
            for ext in extensions.split(','):
                if subdomain.endswith(f'.{ext.strip()}'):
                    filtered_subdomains.add(subdomain)
                    break
        subdomains = filtered_subdomains

    return subdomains

def save_to_file(subdomains, output_file, output_format):
    """Save the subdomains to the specified output file."""
    try:
        if output_format == 'json':
            subdomains_list = list(subdomains)
            subdomains_dict = {'subdomains': subdomains_list}
            with open(output_file, 'w') as file:
                json.dump(subdomains_dict, file, indent=4)
        else:  # Default to CSV format
            with open(output_file, 'w') as file:
                for subdomain in sorted(subdomains):
                    file.write(f"{subdomain}\n")
        logging.info(f"Subdomains saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving to file: {e}")
        print_colored(f"Error saving to file: {e}", Colors.RED)

def display_ascii_art(ascii_art):
    """Display ASCII art."""
    decorative_line = "\n" + "  " + "»" * 78 + "\n"

    total_width = len(decorative_line.strip())
    spaces = " " * ((total_width - len(ascii_art)) // 2)

    print_colored(decorative_line, Colors.GREEN)
    print_colored(spaces + ascii_art, Colors.GREEN)
    print_colored(decorative_line, Colors.GREEN)

if __name__ == "__main__":
    try:
        # ASCII art to display
        ascii_art = """
        █▀ █░█ █▄▄ █░█ █░█ █▄░█ ▀█▀ █▀▀ █▀█
        ▄█ █▄█ █▄█ █▀█ █▄█ █░▀█ ░█░ ██▄ █▀▄
        """

        # Display ASCII art
        display_ascii_art(ascii_art)

        developer_name = "D E V E L O P E D  B Y  K U N A L  N A M D A S"
        total_width = len(ascii_art.strip())
        spaces = " " * ((total_width - len(developer_name)) // 2)
        print(spaces + developer_name, Colors.GREEN)
        print("                                   ")

        # Parse command-line arguments
        args = parse_args()

        # Set up logging
        setup_logging(args.log, args.verbose)

        # Process subdomains based on parsed arguments in one line
        subdomains = process_subdomains(
            args.domain, args.recursive, args.wildcard, 
            args.exclude_wildcards, args.verbose, 
            args.user_agent, args.timeout, args.rate_limit,
            extensions=args.extensions if args.extensions else None
        )

        # Print each subdomain in alphabetical order
        for subdomain in sorted(subdomains):
            print_colored(f"[+] {subdomain}", Colors.BLUE)

        # Save subdomains to the specified output file if provided
        if args.output:
            save_to_file(subdomains, args.output, args.format)

    except Exception as e:
        print_colored(f"Error: {e}", Colors.RED)
