#!/usr/bin/python

# General imports
import logging


# Set logging level
logging.basicConfig(level=logging.DEBUG)


class LocalStorageDriver:

    def __init__(self, host=None,
                 port=None,
                 username=None,
                 password=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client = None
        # Last used STAMP Session Identifier (SSID)
        # In our implementation, SSID 0 is reserved; therefore, the first
        # usable SSID is 1
        self.last_ssid = dict()
        # Pool of SSID allocated to STAMP Sessions terminated
        # These can be reused for other STAMP Sessions
        self.reusable_ssid = dict()
        # Dict mapping node node_id to STAMPNode instance
        self.stamp_nodes = dict()
        # STAMP Sessions
        self.stamp_sessions = dict()

    def create_stamp_session(self, session, tenantid):
        """
        Store a new STAMP session.
        """

        # Store STAMP Session
        if tenantid not in self.stamp_sessions:
            self.stamp_sessions[tenantid] = dict()
        self.stamp_sessions[tenantid][session.ssid] = session

        # Increase sessions counter on the Sender and Reflector
        session.sender.sessions_count += 1
        session.reflector.sessions_count += 1

        return True

    def remove_stamp_session(self, ssid, tenantid):
        """
        Remove a STAMP session.
        """

        # Retrieve STAMP Session
        stamp_session = self.stamp_sessions[tenantid].get(ssid)
        if stamp_session is None:
            return False

        # Remove the STAMP Session from the STAMP Sessions dict
        del self.stamp_sessions[tenantid][ssid]

        # Decrease sessions counter on the Sender and Reflector
        stamp_session.sender.sessions_count -= 1
        stamp_session.reflector.sessions_count -= 1

        return True

    # Remove all the STAMP sessions of a tenant

    def remove_stamp_sessions_by_tenantid(self, tenantid):
        # TODO
        raise NotImplementedError

    # Remove all the STAMP sessions

    def remove_all_stamp_sessions(self):
        # TODO
        raise NotImplementedError

    def get_stamp_sessions(self, session_ids=None, tenantid=None,
                           return_dict=False):
        """
        Get STAMP sessions.
        """

        if tenantid not in self.stamp_sessions:
            return []

        if return_dict:
            if session_ids is None:
                return self.stamp_sessions[tenantid]
            stamp_sessions = dict()
            for ssid in session_ids:
                stamp_sessions[ssid] = self.stamp_sessions[tenantid][ssid]
            return stamp_sessions
        else:
            if session_ids is None:
                return self.stamp_sessions[tenantid].values()
            stamp_sessions = list()
            for ssid in session_ids:
                stamp_sessions.append(self.stamp_sessions[tenantid][ssid])
            return stamp_sessions

    def get_stamp_session(self, ssid, tenantid):
        """
        Get a STAMP session.
        """

        return self.stamp_sessions[tenantid].get(ssid, None)

    def stamp_session_exists(self, ssid, tenantid):
        """
        Return True if a STAMP session exists, False otherwise.
        """

        return ssid in self.stamp_sessions[tenantid]

    # Return True if all the STAMP sessions exist,
    # False otherwise

    def stamp_sessions_exists(self, session_ids):
        # TODO
        raise NotImplementedError

    # Return True if a STAMP session exists and is running,
    # False otherwise

    def is_stamp_session_running(self, ssid, tenantid):
        # Get the STAMP session
        logging.debug('Searching the STAMP session %s (tenant %s)'
                      % (ssid, tenantid))
        session = self.get_stamp_session(ssid, tenantid)
        res = None
        if session is not None:
            # Get the status of the STAMP session
            res = session['is_running']
            if res:
                logging.debug('The device is running')
            else:
                logging.debug('The device is not running')
        # Return True if the STAMP session is running,
        # False if it is not running or
        # None if an error occurred during the connection to the db
        return res

    def set_session_running(self, ssid, tenantid, is_running=True):
        self.stamp_sessions[tenantid][ssid].is_running = is_running

    def create_stamp_node(self, node, tenantid):
        """
        Store a new STAMP Node.
        """

        # Create the tenant's data structure, if it does not exist
        if tenantid not in self.stamp_nodes:
            self.stamp_nodes[tenantid] = dict()
            self.stamp_sessions[tenantid] = dict()
            self.last_ssid[tenantid] = 0
            self.reusable_ssid[tenantid] = set()

        self.stamp_nodes[tenantid][node.node_id] = node

        return True

    def update_stamp_node(self, node, tenantid, grpc_ip=None, grpc_port=None):
        """
        Update an existing STAMP Node.
        """
        raise NotImplementedError

    def remove_stamp_node(self, node_id, tenantid):
        """
        Remove a STAMP Node.
        """

        del self.stamp_nodes[tenantid][node_id]

        # Remove the tenant's data structure if empty
        if len(self.stamp_nodes[tenantid]) == 0:
            del self.stamp_nodes[tenantid]

        return True

    # Remove all the STAMP nodes of a tenant

    def remove_stamp_nodes_by_tenantid(self, tenantid):
        # TODO
        raise NotImplementedError

    # Remove all the STAMP nodes

    def remove_all_stamp_nodes(self):
        # TODO
        raise NotImplementedError

    # Get STAMP nodes

    def get_stamp_nodes(self, node_ids=None, tenantid=None,
                        return_dict=False):
        """
        Get STAMP nodes.
        """

        if return_dict:
            stamp_nodes = dict()
            for ssid in node_ids:
                stamp_nodes[ssid] = self.stamp_nodes[tenantid][ssid]
            return stamp_nodes
        else:
            stamp_nodes = list()
            for ssid in node_ids:
                stamp_nodes.append(self.stamp_nodes[tenantid][ssid])
            return stamp_nodes

    def get_stamp_node(self, node_id, tenantid):
        """
        Get a STAMP node.
        """

        if tenantid not in self.stamp_nodes:
            return None

        return self.stamp_nodes[tenantid].get(node_id, None)

    def set_sender_inizialized(self, node_id, tenantid,
                               is_initialized=True):
        self.stamp_nodes[tenantid][node_id].is_sender_initialized = \
            is_initialized

    def set_reflector_inizialized(self, node_id, tenantid,
                                  is_initialized=True):
        self.stamp_nodes[tenantid][node_id].is_reflector_initialized = \
            is_initialized

    # Return True if a STAMP node exists,
    # False otherwise

    def stamp_node_exists(self, node_id, tenantid):
        # TODO
        raise NotImplementedError

    # Return True if all the STAMP nodes exist,
    # False otherwise

    def stamp_nodes_exists(self, node_ids):
        # TODO
        raise NotImplementedError

    # Return True if a STAMP node exists and is a sender,
    # False otherwise

    def is_stamp_sender(self, node_id, tenantid):
        # Get the STAMP node
        logging.debug('Searching the STAMP node %s (tenant %s)'
                      % (node_id, tenantid))
        node = self.get_stamp_node(node_id, tenantid)
        res = None
        if node is not None:
            # Get the status of the STAMP node
            res = node['is_sender']
            if res:
                logging.debug('The STAMP node is a sender')
            else:
                logging.debug('The STAMP node is not sender')
        # Return True if the STAMP node is a sender,
        # False if it is not a sender or
        # None if an error occurred during the connection to the db
        return res

    # Return True if a STAMP node exists and is a reflector,
    # False otherwise

    def is_stamp_reflector(self, node_id, tenantid):
        # Get the STAMP node
        logging.debug('Searching the STAMP node %s (tenant %s)'
                      % (node_id, tenantid))
        node = self.get_stamp_node(node_id, tenantid)
        res = None
        if node is not None:
            # Get the status of the STAMP node
            res = node['is_reflector']
            if res:
                logging.debug('The STAMP node is a reflector')
            else:
                logging.debug('The STAMP node is not reflector')
        # Return True if the STAMP node is a reflector,
        # False if it is not a reflector or
        # None if an error occurred during the connection to the db
        return res

    def set_mean_delay(self, ssid, tenantid, mean_delay,
                       direction='direct_path'):
        # TODO
        raise NotImplementedError

    def add_delay(self, ssid, tenantid, new_delay,
                  direction='direct_path'):
        # TODO
        raise NotImplementedError

    def increase_sessions_count(self, node_id, tenantid):
        self.stamp_nodes[tenantid][node_id].sessions_count += 1

    def decrease_sessions_count(self, node_id, tenantid):
        self.stamp_nodes[tenantid][node_id].sessions_count -= 1

    def get_new_ssid(self, tenantid):
        """
        Allocate and return a new SSID for a STAMP Session.
        """

        # Pick a SSID from the reusable SSIDs pool
        # If the pool is empty, we take a new SSID
        if len(self.reusable_ssid[tenantid]) > 0:
            ssid = self.reusable_ssid[tenantid].pop()
        else:
            ssid = self.last_ssid[tenantid] + 1
            self.last_ssid[tenantid] += 1

        return ssid

    def release_ssid(self, ssid, tenantid):
        """
        Release a SSID and mark it as reusable.
        """

        # Mark the SSID as reusable
        self.reusable_ssid[tenantid].add(ssid)

        return True

    def add_delay_and_update_average(self, ssid, tenantid, new_delay,
                                     direction='direct_path'):
        if direction == 'direct_path':
            self.stamp_sessions[tenantid][ssid].stamp_session_direct_path_results.add_new_delay(new_delay)
        else:
            self.stamp_sessions[tenantid][ssid].stamp_session_return_path_results.add_new_delay(new_delay)
