#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

INTERVAL = 1
COST = 10
BLOCKING = "BLOCKING"
LISTENING = "LISTENING"
DESIGNATED = "DESIGNATED"

root_bridge_id = None
own_bridge_id = None
root_path_cost = 0
root_port = None
port_states = {}


def stp_init(priority, trunk_ports):
    global root_bridge_id, own_bridge_id, root_path_cost, root_port, port_states
    own_bridge_id = priority
    root_bridge_id = own_bridge_id
    root_port = None
    root_path_cost = 0

    for port in trunk_ports:
        port_states[port] = BLOCKING

    if own_bridge_id == root_bridge_id:
        for port in port_states:
            port_states[port] = DESIGNATED



def stp_receive_bpdu(port, data):
    global root_bridge_id, root_path_cost, root_port, port_states
    #unpack the data
    bpdu_root_id, bpdu_sender_id, bpdu_path_cost = struct.unpack('!QQQ', data)

    #in case of a new root
    if bpdu_root_id < root_bridge_id:
        root_bridge_id = bpdu_root_id
        root_path_cost = bpdu_path_cost + COST
        root_port = port

        #set all ports to blocking except the root port
        for p in port_states:
            port_states[p] = BLOCKING

        port_states[port] = LISTENING

        #forward the BPDU
        stp_forward()
    
    #in case of the same root bridge
    elif bpdu_root_id  == root_bridge_id:
        if port == root_port and bpdu_path_cost + COST < root_path_cost:
            root_path_cost = bpdu_path_cost + COST
        elif port != root_port and bpdu_path_cost > root_path_cost:
            if port_states[port] != LISTENING:
                port_states[port] = LISTENING

    #in case the bpdu was sent from self
    elif bpdu_sender_id == own_bridge_id:
        port_states[port] = BLOCKING



def stp_forward():
    bpdu = struct.pack('!QQQ', root_bridge_id, own_bridge_id, root_path_cost)
    for port in port_states:
        if port != root_port and port_states[port] != BLOCKING:
            send_to_link(port, len(bpdu), bpdu)


def parse_sw_config(config):
    acces_vlan_table = {}
    sw_prio = 0
    port_type = {}

    with open(config, 'r') as f:
        lines = f.readlines()

        sw_prio = int(lines[0].strip())

        for line in lines[1:]:
            words = line.strip().split()
            interface = words[0]

            #check for port type:
            if words[1] == 'T':
                port_type[interface] = 'T'
                acces_vlan_table[interface] = -1
            else:
                #acces port:
                vlan = int(words[1])
                port_type[interface] = 'A'
                acces_vlan_table[interface] = vlan

    return sw_prio, acces_vlan_table, port_type



def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    #periodically sending BPDU if switch is root
    while True:
        if own_bridge_id == root_bridge_id:
            bpdu = struct.pack('!QQQ', root_bridge_id, own_bridge_id, root_path_cost)
            for port, state in port_states.items():
                if state != BLOCKING:
                    send_to_link(port, len(bpdu), bpdu)

        time.sleep(INTERVAL)


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    mac_table = {}

    switch_id = sys.argv[1]
    conf_file = f"configs/switch{switch_id}.cfg"

    #parsing the config file:
    sw_prio, acces_vlan_table, port_type = parse_sw_config(conf_file)


    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    #setup the STP
    trunk_ports = [i for i in interfaces if port_type[get_interface_name(i)] == 'T']
    stp_init(sw_prio, trunk_ports)

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()


    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        if port_states.get(interface) == BLOCKING:
            continue
        interface_name = get_interface_name(interface)

        #check for bpdu pakets
        if length == 24:
            stp_receive_bpdu(interface, data)
            continue

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        if port_type[interface_name] == 'T':
            cameFromTrunk = True
        else:
            cameFromTrunk = False
        #vlan filtering:
        if port_type[interface_name] == 'A':
            if vlan_id == -1:
                #data comming from a device
                vlan_id = acces_vlan_table[interface_name]
            elif vlan_id != acces_vlan_table[interface_name]:
                #invalid vlan
                continue
        elif port_type[interface_name] == 'T' and vlan_id == -1:
            # an untagged packet wants to travel trough a trunk type port
            continue

        if src_mac not in mac_table:
            mac_table[src_mac] = interface
        elif mac_table[src_mac] != interface:
            #update the entry
            mac_table[src_mac] = interface

        if dest_mac in mac_table:
            dest_interface = mac_table[dest_mac]
            dest_interface_name = get_interface_name(dest_interface)
            if dest_interface != interface: #for loop avoidance
                if port_type[dest_interface_name] == 'T' and vlan_id != -1:
                    if cameFromTrunk:
                        send_to_link(dest_interface, length, data)
                    else:
                        tagged_frame = data[:12] + create_vlan_tag(vlan_id) + data[12:]
                        send_to_link(dest_interface, length + 4, tagged_frame)
                else:
                    if cameFromTrunk:
                        tagged_frame = data[:12] + data[16:]
                        send_to_link(dest_interface, length - 4, tagged_frame)
                    else:
                        send_to_link(dest_interface, length, data)
        else:
            #flooding
            for i in interfaces:
                if i != interface and (port_type[get_interface_name(i)] == 'T' or acces_vlan_table.get(get_interface_name(i)) == vlan_id):
                    if port_type[get_interface_name(i)] == 'T':

                        if cameFromTrunk:
                            send_to_link(i, length, data)
                        else:
                            tagged_frame = data[:12] + create_vlan_tag(vlan_id) + data[12:]
                            send_to_link(i, length + 4, tagged_frame)
                    else:
                        if cameFromTrunk:
                            tagged_frame = data[:12] + data[16:]
                            send_to_link(i, length - 4, tagged_frame)
                        else:
                            send_to_link(i, length, data)

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()
