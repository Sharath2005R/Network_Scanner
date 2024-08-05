import scapy.all as scapy
import optparse

def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Enter the IP Address range")
    (options, arguments) = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify the Range of the IP Address. Use --help for more information.")

    return options

def scan(ip):
    print(f"Scanning IP range: {ip}")  # Debug print to verify IP range
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=True)[0]  # Set verbose to True

    client_list = []
    for ans in answered:
        client_dict = {"IP Address": ans[1].psrc, "MAC Address": ans[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_output(scanned_list):
    if not scanned_list:
        print("No devices found.")
    else:
        print("IP Address\t\t MAC Address")
        print("- - - - - - - - - - - - - - - - - - - - - ")
        for ans in scanned_list:
            print(ans["IP Address"] + "\t\t" + ans["MAC Address"])

# Main execution
ip_input = get_args()
scanned_list = scan(ip_input.target)
print()
print_output(scanned_list)
