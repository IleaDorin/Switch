1 2 3

# Ethernet Switch Implementation

## Implementation Details

### 1. MAC Address Learning and Frame Forwarding

The switch uses a MAC learning table to associate source MAC addresses 
with incoming ports. When a frame arrives, the switch checks the MAC 
table:

- **Unicast Frame**: If the destination MAC is in the table, the frame is 
  forwarded to the corresponding port. If not, the frame is flooded to 
  other relevant ports.
- **Broadcast Frame**: If the destination MAC is not mapped, it is sent to all 
  ports within the same VLAN if VLANs are enabled.

### 2. VLAN Support

The switch handles VLANs using IEEE 802.1Q tagging:

- **Trunk Ports**: Carry frames tagged with VLAN IDs and connect to other 
  switches, allowing traffic between VLANs.
- **Access Ports**: Manage traffic to end hosts, tagging frames with the 
  port's VLAN ID or stripping tags when appropriate.

For forwarding:
- **Tagged Frames**: Trunk ports handle frames with VLAN tags, while 
  access ports add or remove tags as per configuration.

### 3. Spanning Tree Protocol (STP)

The Spanning Tree Protocol (STP) prevents loops in network topologies 
with redundant paths by electing a root bridge and assigning port roles.

- **BPDU Exchange**: Bridge Protocol Data Units (BPDUs) are used to 
  determine the root bridge and update path costs. 
- **Port States**: Ports can be `BLOCKING`, `LISTENING`, or `DESIGNATED`, 
  determined through BPDU messages to prevent loops.
- **Periodic BPDU Broadcasting**: The root switch sends BPDUs every 
  second on all non-blocking trunk ports to maintain network state.

### STP Workflow

1. **Initialization**: Each switch initializes by setting trunk ports to 
   `DESIGNATED`, assuming itself as the root bridge.
2. **BPDU Transmission**: The root switch sends BPDUs every second to 
   declare its status.
3. **BPDU Reception and Role Adjustment**: Upon receiving a BPDU, the 
   switch compares root IDs, updates its root bridge, path cost, and 
   port states as necessary.
4. **Forwarding Control**: Frames are only received if they come from
a non `BLOCKING` port.

## Function Descriptions

### 1. `stp_init(priority, trunk_ports)`
Initializes STP by setting the root bridge ID, path cost, and marking all 
trunk ports as `BLOCKING` initially but because all of them think they are
the root bridge they mark the ports as `DESIGNATED`.

### 2. `stp_receive_bpdu(port, data)`
Processes incoming BPDUs to update root bridge information, port states, 
and root path cost as per STP rules.

### 3. `stp_forward()`
Creates and forwards BPDUs on non-blocking trunk ports.

### 4. `parse_sw_config(config)`
Reads switch configuration, setting VLAN IDs and designating each port as 
`trunk` or `access` based on the config file.

### 5. `parse_ethernet_header(data)`
Extracts source MAC, destination MAC, EtherType, and VLAN ID from an 
incoming Ethernet frame.

### 6. `create_vlan_tag(vlan_id)`
Creates a VLAN tag with `0x8200` as the Ethertype and adds the specified 
VLAN ID for tagging.

### 7. `send_bdpu_every_sec()`
Periodically sends BPDUs every second from the root bridge to maintain 
network state.

### 8. `main()`
Initializes the switch, loads configuration, sets up STP and VLANs, and 
handles frame processing, learning, and forwarding.

## BPDU Encoding/Decoding
The BPDU struct uses `!QQQ` encoding: three 64-bit integers representing 
the root bridge ID, sender bridge ID, and path cost.

