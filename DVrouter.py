from router import Router
import json
from packet import Packet


class DVrouter(Router):
    """Distance vector routing protocol implementation.

    Add your own class fields and initialization code (e.g. to create forwarding table
    data structures). See the `Router` base class for docstrings of the methods to
    override.
    """

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Initialize base class - DO NOT REMOVE
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.dv = {addr: (0, None)}
        self.neighbors = {}
        self.forwarding_table = {}
        self.INFINITY = 16
        self.neighbor_dvs = {}

    def handle_packet(self, port, packet):
        """Process incoming packet."""
        if packet.is_traceroute:
            if packet.dst_addr in self.forwarding_table:
                self.send(self.forwarding_table[packet.dst_addr], packet)
        else:
            try:
                neighbor_addr = packet.src_addr
                neighbor_dv = json.loads(packet.content)

                self.neighbor_dvs[neighbor_addr] = neighbor_dv

                dv_changed = False

                for dest, cost in neighbor_dv.items():
                    if port in self.neighbors:
                        neighbor_cost = self.neighbors[port][1]
                        new_cost = neighbor_cost + cost

                        # new dest or shorter path
                        if dest not in self.dv or new_cost < self.dv[dest][0]:
                            if new_cost < self.INFINITY:
                                self.dv[dest] = (new_cost, port)
                                self.forwarding_table[dest] = port
                                dv_changed = True

                        # old dest and changed cost
                        elif self.dv[dest][1] == port and new_cost != self.dv[dest][0]:
                            # unreachable
                            if new_cost >= self.INFINITY:
                                if dest in self.forwarding_table:
                                    del self.forwarding_table[dest]
                                self.dv[dest] = (self.INFINITY, None)

                                best_cost = self.INFINITY
                                best_port = None

                                # find alternative path
                                for alt_port, (
                                    alt_neighbor,
                                    alt_cost,
                                ) in self.neighbors.items():
                                    if alt_port != port:
                                        if alt_neighbor == dest:
                                            if alt_cost < best_cost:
                                                best_cost = alt_cost
                                                best_port = alt_port
                                        elif (
                                            alt_neighbor in self.neighbor_dvs
                                            and dest in self.neighbor_dvs[alt_neighbor]
                                        ):
                                            alt_total_cost = (
                                                alt_cost
                                                + self.neighbor_dvs[alt_neighbor][dest]
                                            )
                                            if alt_total_cost < best_cost:
                                                best_cost = alt_total_cost
                                                best_port = alt_port

                                if best_port is not None:
                                    self.dv[dest] = (best_cost, best_port)
                                    self.forwarding_table[dest] = best_port

                            # reachable route with new cost
                            else:
                                self.dv[dest] = (new_cost, port)
                                self.forwarding_table[dest] = port
                            dv_changed = True

                if dv_changed:
                    self.broadcast_dv()
            except Exception as e:
                print(f"Error processing routing packet: {e}")

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        self.neighbors[port] = (endpoint, cost)
        self.dv[endpoint] = (cost, port)
        self.forwarding_table[endpoint] = port
        self.broadcast_dv()
        self.send_dv(port)

    def handle_remove_link(self, port):
        """Handle removed link."""
        if port in self.neighbors:
            removed_neighbor, _ = self.neighbors[port]
            del self.neighbors[port]

            if removed_neighbor in self.neighbor_dvs:
                del self.neighbor_dvs[removed_neighbor]

            dv_changed = False

            # check destination currently routing through the failed link
            invalidated_dests = []
            for dest in list(self.dv.keys()):
                if self.dv[dest][1] == port:
                    self.dv[dest] = (self.INFINITY, None)
                    if dest in self.forwarding_table:
                        del self.forwarding_table[dest]
                    invalidated_dests.append(dest)
                    dv_changed = True

            # find alternative path for unreachable dest
            for dest in invalidated_dests:
                best_cost = self.INFINITY
                best_port = None

                for alt_port, (alt_neighbor, alt_cost) in self.neighbors.items():
                    if alt_neighbor == dest:
                        if alt_cost < best_cost:
                            best_cost = alt_cost
                            best_port = alt_port
                    elif (
                        alt_neighbor in self.neighbor_dvs
                        and dest in self.neighbor_dvs[alt_neighbor]
                    ):
                        alt_total_cost = (
                            alt_cost + self.neighbor_dvs[alt_neighbor][dest]
                        )
                        if alt_total_cost < best_cost:
                            best_cost = alt_total_cost
                            best_port = alt_port

                if best_port is not None:
                    self.dv[dest] = (best_cost, best_port)
                    self.forwarding_table[dest] = best_port
                    dv_changed = True

            if dv_changed:
                self.broadcast_dv()

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.broadcast_dv()

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        result = f"DVrouter(addr={self.addr})\n"
        result += "Distance Vector:\n"
        for dest, (cost, port) in sorted(self.dv.items()):
            result += f"  {dest}: cost={cost}, port={port}\n"
        result += "Forwarding Table:\n"
        for dest, port in sorted(self.forwarding_table.items()):
            result += f"  {dest} -> port {port}\n"
        return result

    def broadcast_dv(self):
        for port in self.neighbors:
            self.send_dv(port)

    def send_dv(self, port):
        neighbor_addr = self.neighbors[port][0]
        poisoned_dv = {}

        for dest, (cost, outport) in self.dv.items():
            if dest == self.addr:
                poisoned_dv[dest] = 0
            elif dest == neighbor_addr:
                direct_cost = self.neighbors[port][1]
                poisoned_dv[dest] = direct_cost
            # poison reverse - advertise destination unreachble if reached through a neighbor
            elif outport == port:
                poisoned_dv[dest] = self.INFINITY
            else:
                poisoned_dv[dest] = cost

        dv_str = json.dumps(poisoned_dv)
        packet = Packet(Packet.ROUTING, self.addr, neighbor_addr, dv_str)
        self.send(port, packet)
