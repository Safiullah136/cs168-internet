"""
Your awesome Distance Vector router for CS 168

Based on skeleton code by:
  MurphyMc, zhangwen0411, lab352
"""

import sim.api as api
from cs168.dv import (
    RoutePacket,
    Table,
    TableEntry,
    DVRouterBase,
    Ports,
    FOREVER,
    INFINITY,
)


class DVRouter(DVRouterBase):

    # A route should time out after this interval
    ROUTE_TTL = 15

    # -----------------------------------------------
    # At most one of these should ever be on at once
    SPLIT_HORIZON = False
    POISON_REVERSE = True
    # -----------------------------------------------

    # Determines if you send poison for expired routes
    POISON_EXPIRED = True

    # Determines if you send updates when a link comes up
    SEND_ON_LINK_UP = False

    # Determines if you send poison when a link goes down
    POISON_ON_LINK_DOWN = False

    def __init__(self):
        """
        Called when the instance is initialized.
        DO NOT remove any existing code from this method.
        However, feel free to add to it for memory purposes in the final stage!
        """
        assert not (
            self.SPLIT_HORIZON and self.POISON_REVERSE
        ), "Split horizon and poison reverse can't both be on"

        self.start_timer()  # Starts signaling the timer at correct rate.

        # Contains all current ports and their latencies.
        # See the write-up for documentation.
        self.ports = Ports()
        self.history = dict()

        # This is the table that contains all current routes
        self.table = Table()
        self.table.owner = self

        ##### Begin Stage 10A #####

        ##### End Stage 10A #####

    def add_static_route(self, host, port):
        """
        Adds a static route to this router's table.

        Called automatically by the framework whenever a host is connected
        to this router.

        :param host: the host.
        :param port: the port that the host is attached to.
        :returns: nothing.
        """
        # `port` should have been added to `peer_tables` by `handle_link_up`
        # when the link came up.
        assert port in self.ports.get_all_ports(), "Link should be up, but is not."

        ##### Begin Stage 1 #####

        self.table[host] = TableEntry(host, port, self.ports.get_latency(port), FOREVER)         

        ##### End Stage 1 #####

    def handle_data_packet(self, packet, in_port):
        """
        Called when a data packet arrives at this router.

        You may want to forward the packet, drop the packet, etc. here.

        :param packet: the packet that arrived.
        :param in_port: the port from which the packet arrived.
        :return: nothing.
        """
        
        ##### Begin Stage 2 #####

        entry = self.table.get(packet.dst)
        if entry is None or entry.latency >= INFINITY:
            return 

        self.send(packet, port=entry.port)

        ##### End Stage 2 #####


    def handleForceFalse(self, port, dst, entry_latency, entry_port):
        if self.history.get(port) is None:
            self.history[port] = {}

        port_entry = self.history[port]
        if port_entry.get(dst) is None or port_entry.get(dst) != entry_latency:
            self.send_route(port, dst, entry_latency)
            self.history[port][dst] = entry_latency
         

    def send_routes(self, force=False, single_port=None):
        """
        Send route advertisements for all routes in the table.

        :param force: if True, advertises ALL routes in the table;
                      otherwise, advertises only those routes that have
                      changed since the last advertisement.
               single_port: if not None, sends updates only to that port; to
                            be used in conjunction with handle_link_up.
        :return: nothing.
        """
        
        ##### Begin Stages 3, 6, 7, 8, 10 #####

        loop_ports = self.ports.get_all_ports()
        if single_port:
            loop_ports = [single_port]

        for dst, entry in self.table.items():
            for port in loop_ports:
                if self.SPLIT_HORIZON and entry.port == port:
                    continue

                latency = entry.latency
                if latency >= INFINITY or (self.POISON_REVERSE and entry.port == port):
                    latency = INFINITY

                if force:
                    self.send_route(port, dst, latency)

                else:
                    self.handleForceFalse(port, dst, latency, entry.port)
                                
                        

        ##### End Stages 3, 6, 7, 8, 10 #####

    def updateEntryAndAdvertise(self, dst, port, latency, expire_time):
        self.table[dst] = TableEntry(dst, port, latency, expire_time)

    def expire_routes(self):
        """
        Clears out expired routes from table.
        accordingly.
        """
        
        ##### Begin Stages 5, 9 #####

        for dst in list(self.table):
            if self.table[dst].expire_time <= api.current_time():
                if not self.POISON_EXPIRED:
                    self.table.pop(dst)
                else:
                    entry = self.table[dst]
                    self.updateEntryAndAdvertise(dst, entry.port, INFINITY, api.current_time()+self.ROUTE_TTL)
                
                self.s_log(f"Link from router {dst} to router {self.name} is expired.")

        ##### End Stages 5, 9 #####

    def handle_route_advertisement(self, route_dst, route_latency, port):
        """
        Called when the router receives a route advertisement from a neighbor.

        :param route_dst: the destination of the advertised route.
        :param route_latency: latency from the neighbor to the destination.
        :param port: the port that the advertisement arrived on.
        :return: nothing.
        """
        
        ##### Begin Stages 4, 10 #####
        link_latency = self.ports.get_latency(port)
        entry = self.table.get(route_dst)

        if entry is None or entry.port == port or route_latency + link_latency < entry.latency:
            self.updateEntryAndAdvertise(route_dst, port, route_latency + link_latency, api.current_time()+self.ROUTE_TTL)
            self.send_routes(force=False)

        ##### End Stages 4, 10 #####

    def handle_link_up(self, port, latency):
        """
        Called by the framework when a link attached to this router goes up.

        :param port: the port that the link is attached to.
        :param latency: the link latency.
        :returns: nothing.
        """
        self.ports.add_port(port, latency)

        ##### Begin Stage 10B #####

        if self.SEND_ON_LINK_UP:
            self.send_routes(force=False, single_port=port)

        ##### End Stage 10B #####

    def handle_link_down(self, port):
        """
        Called by the framework when a link attached to this router goes down.

        :param port: the port number used by the link.
        :returns: nothing.
        """
        self.ports.remove_port(port)

        ##### Begin Stage 10B #####

        for dst in list(self.table):
            if self.table[dst].port != port:
                continue

            if not self.POISON_ON_LINK_DOWN:
                self.table.pop(dst)
            else:
                self.updateEntryAndAdvertise(dst, port, INFINITY, api.current_time()+self.ROUTE_TTL)

        if self.POISON_ON_LINK_DOWN:    
            self.send_routes(force=False)

        ##### End Stage 10B #####

    # Feel free to add any helper methods!
