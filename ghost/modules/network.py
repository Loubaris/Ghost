"""
This module requires Ghost: https://github.com/EntySec/Ghost
Current source: https://github.com/EntySec/Ghost
"""

from ghost.lib.module import Module


class GhostModule(Module):
    def __init__(self):
        super().__init__()

        self.details.update({
            'Category': "manage",
            'Name': "network",
            'Authors': [
                'Loubaris - module developer'
            ],
            'Description': "Retrieve network informations",
            'Usage': "Arguments:\n - scan <0|255>: Scan device's network\n - arptable: Show device ARP Table\n - ipconfig: Show device configuration\n - iproute: Show device's routing table\n - location: Retrieve network location\n - statistics: Show network stats\n - open_ports: Check for open ports\n - service_list: Show all network services\n - forwarding: Check for IP forwarding",
            'MinArgs': 1,
            'NeedsRoot': False
        })
        
    def get_device_ip(self):
        ip_output = self.device.send_command("ifconfig")
        lines = ip_output.split("\n")
        for line in lines:
            if "inet addr" in line:
                ip_address = line.split()[1].split(":")[1]
                return ip_address

    def get_subnet(self, ip_address):
        try:
            subnet_parts = ip_address.split(".")[:-1]
            subnet = ".".join(subnet_parts)
            return subnet
        except:
            print("Error: Scan failed")

    def scan_network(self, subnet, scanrange=255):
        active_hosts = []
        for host in range(1, scanrange):
            ip_address = f"{subnet}.{host}"
            command = f"ping -c 1 -w 1 {ip_address}"
            output = self.device.send_command(command)
            print(output)
            if "1 packets transmitted, 1 received" in output:
                active_hosts.append(ip_address)
        return active_hosts

    def get_device_name(self, ip_address):
        arp_output = self.device.send_command("arp")
        lines = arp_output.split("\n")
        for line in lines:
            if ip_address in line:
                parts = line.split()
                if len(parts) >= 2:
                    return parts[0]
        return None

    def run(self, argc, argv):
        if argv[1] in ['arptable', 'scan', 'ipconfig', 'iproute', 'location', 'statistics', 'open_ports', 'service_list', 'forwarding']:
            if argv[1] == 'scan':
                argv.append('')
                if argv[2] == '':
                    argv[2] = 255

                device_ip = self.get_device_ip()
                subnet = self.get_subnet(device_ip)

                active_hosts = self.scan_network(subnet, int(argv[2]))
                print("Active hosts:")
                for host in active_hosts:
                    device_name = self.get_device_name(host)
                    if device_name:
                        print(f"{host} - {device_name}")
                    else:
                        print(host)
                output = ''
            elif argv[1] == 'arptable':
                output = self.device.send_command('cat /proc/net/arp')
            elif argv[1] == 'ipconfig':
                output = self.device.send_command('ip addr show')
            elif argv[1] == 'iproute':
                output = self.device.send_command('ip route show')
            elif argv[1] == 'location':
                output = self.device.send_command('dumpsys location')
            elif argv[1] == 'statistics':
                output = self.device.send_command('cat /proc/net/netstat')
            elif argv[1] == 'open_ports':
                output = self.device.send_command('busybox netstat -an')
            elif argv[1] == 'service_list':
                output = self.device.send_command('service list')
            elif argv[1] == 'forwarding':
                output = self.device.send_command('cat /proc/sys/net/ipv4/ip_forward')
            print(output)

        else:
            self.print_empty(f"Usage: {self.details['Usage']}")
