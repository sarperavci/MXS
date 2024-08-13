import argparse
from func import MassScanner
from colorama import init

init(autoreset=True)

argparser = argparse.ArgumentParser(description="Mass XSS Scanner")

argparser.add_argument("-i", "--input", help="URLs to scan", type=str, required=True)
argparser.add_argument("-o", "--output", help="Output file", type=str, default="vulnerable_urls.txt")
argparser.add_argument("-c", "--concurrency", help="Number of concurrent requests", type=int, default=50)
argparser.add_argument("-t", "--timeout", help="Request timeout", type=float, default=15)
argparser.add_argument("-p", "--payload", help="XSS payload File (Only one payload)", type=str, required=False)
argparser.add_argument("-x", "--hidden", help="Redact domains in the terminal output", action="store_true")

args = argparser.parse_args()


if __name__ == "__main__":
    scanner = MassScanner(args.input, args.output , args.concurrency, args.timeout, args.payload, args.hidden)
    scanner.run()