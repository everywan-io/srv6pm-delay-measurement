#!/usr/bin/python

# General imports
import pymongo
import logging
import time
import urllib.parse

from .controller_utils import (
    STAMPNode,
    STAMPSession,
    STAMPSessionResults,
    compute_mean_delay_welford
)


# Global variables
DEFAULT_MONGODB_HOST = '0.0.0.0'
DEFAULT_MONGODB_PORT = 27017
DEFAULT_MONGODB_USERNAME = 'root'
DEFAULT_MONGODB_PASSWORD = '12345678'

RESERVED_SSID = []


# Set logging level
logging.basicConfig(level=logging.DEBUG)


class MongoDBDriver:

    def __init__(self, host=DEFAULT_MONGODB_HOST,
                 port=DEFAULT_MONGODB_PORT,
                 username=DEFAULT_MONGODB_USERNAME,
                 password=DEFAULT_MONGODB_PASSWORD,
                 mongodb_client=None):
        self.host = host
        if self.host is None:
            self.host = DEFAULT_MONGODB_HOST
        self.port = port
        if self.port is None:
            self.port = DEFAULT_MONGODB_PORT
        self.username = username
        if self.username is None:
            self.username = DEFAULT_MONGODB_USERNAME
        self.password = password
        if self.password is None:
            self.password = DEFAULT_MONGODB_PASSWORD
        self.client = mongodb_client

    # Get a reference to the MongoDB client
    def get_mongodb_session(self):
        # Percent-escape username
        username = urllib.parse.quote_plus(self.username)
        # Percent-escape password
        password = urllib.parse.quote_plus(self.password)
        # Return the MongoDB client
        logging.debug('Trying to establish a connection '
                      'to the db (%s:%s)' % (self.host, self.port))
        # Adjust IP address representation
        host = '[%s]' % self.host
        if self.client is None:
            self.client = pymongo.MongoClient(host=host,
                                              port=self.port,
                                              username=username,
                                              password=password)
        return self.client

    def create_stamp_session(self, session, tenantid):
        """
        Store a new STAMP session.
        """

        # Build the document to insert
        session = {
            'ssid': session.ssid,
            'description': session.description,
            'sender_id': session.sender.node_id,
            'reflector_id': session.reflector.node_id,
            'sidlist': session.sidlist,
            'return_sidlist': session.return_sidlist,
            'interval': session.interval,
            'auth_mode': session.auth_mode,
            'sender_key_chain': session.sender_key_chain,
            'reflector_key_chain': session.reflector_key_chain,
            'sender_timestamp_format': session.sender_timestamp_format,
            'reflector_timestamp_format': session.reflector_timestamp_format,
            'packet_loss_type': session.packet_loss_type,
            'delay_measurement_mode': session.delay_measurement_mode,
            'session_reflector_mode': session.session_reflector_mode,
            'is_running': session.is_running,
            'duration': session.duration,
            'results': {
                'direct_path': {
                    'delays': [],
                    'average_delay': 0.0,
                    'count_packets': 0,
                    'last_result_id': -1
                },
                'return_path': {
                    'delays': [],
                    'average_delay': 0.0,
                    'count_packets': 0,
                    'last_result_id': -1
                }
            },
            'tenantid': tenantid
        }
        # Register the session
        logging.debug('Registering session on DB: %s' % session)
        success = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the sessions collection
            stamp_sessions = db.stamp_sessions
            # Add the session to the collection
            success = stamp_sessions.insert_one(session).acknowledged
            if success:
                logging.debug('STAMP session successfully registered')
            else:
                logging.error('Cannot create the STAMP session')
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return
        return success

    def remove_stamp_session(self, ssid, tenantid):
        """
        Remove a STAMP session.
        """

        # Build the document to remove
        session = {'ssid': ssid, 'tenantid': tenantid}
        # Remove the session
        logging.debug('Removing STAMP session: %s (tenant %s)'
                      % (ssid, tenantid))
        success = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP sessions collection
            stamp_sessions = db.stamp_sessions
            # Decrease session count for Sender and Reflectors
            stamp_nodes = db.stamp_nodes
            # Build the query
            query = {'ssid': ssid, 'tenantid': tenantid}
            stamp_session = stamp_sessions.find_one(query)
            query = {
                'node_id': stamp_session['sender_id'], 'tenantid': tenantid}
            # Build the update
            update = {'$inc': {'sessions_count': -1}}
            # Decrease the sessions count
            stamp_nodes.find_one_and_update(
                query, update)
            # Build the query
            query = {
                'node_id': stamp_session['reflector_id'], 'tenantid': tenantid}
            # Build the update
            update = {'$inc': {'sessions_count': -1}}
            # Decrease the sessions count
            stamp_nodes.find_one_and_update(
                query, update)
            # Delete the STAMP session from the collection
            success = stamp_sessions.delete_one(session).deleted_count == 1
            if success:
                logging.debug('STAMP session removed successfully')
            else:
                logging.error('Cannot remove the STAMP session')
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return
        return success

    # Remove all the STAMP sessions of a tenant

    def remove_stamp_sessions_by_tenantid(self, tenantid):
        # Build the filter
        sessions = {'tenantid': tenantid}
        # Delete all the STAMP sessions in the collection
        logging.debug(
            'Unregistering all the STAMP sessions of the tenant %s' % tenantid)
        success = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP sessions collection
            stamp_sessions = db.stamp_sessions
            success = stamp_sessions.delete_many(sessions).acknowledged
            if success:
                logging.debug('Devices successfully unregistered')
            else:
                logging.error('Cannot remove the STAMP sessions')
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return
        return success

    # Remove all the STAMP sessions

    def remove_all_stamp_sessions(self):
        # Delete all the STAMP sessions in the collection
        logging.debug('Removing all the STAMP sessions')
        success = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP sessions collection
            stamp_sessions = db.stamp_sessions
            success = stamp_sessions.delete_many().acknowledged
            if success:
                logging.debug('STAMP sessions successfully removed')
            else:
                logging.error('Cannot remove the STAMP sessions')
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return
        return success

    # Get STAMP sessions

    def get_stamp_sessions(self, session_ids=None, tenantid=None,
                           return_dict=False):
        # Build the query
        query = dict()
        if tenantid is not None:
            query['tenantid'] = tenantid
        if session_ids is not None:
            query['ssid'] = {'$in': list(session_ids)}
        # Find the STAMP session by SSID
        logging.debug('Retrieving STAMP sessions [%s] by tenant ID %s' % (
            session_ids, tenantid))
        res = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP sessions collection
            stamp_sessions = db.stamp_sessions
            # Find the STAMP sessions
            stamp_sessions = stamp_sessions.find(query)

            sessions = list()
            for session in stamp_sessions:
                sender = self.get_stamp_nodes(
                    node_ids=[session['sender_id']], tenantid=tenantid)[0]
                if session['sender_id'] == session['reflector_id']:
                    reflector = sender
                else:
                    reflector = self.get_stamp_nodes(
                        node_ids=[session['reflector_id']], tenantid=tenantid)[0]

                # Parse session
                sess = STAMPSession(
                    ssid=session['ssid'],
                    description=session['description'],
                    sender=sender,
                    reflector=reflector,
                    sidlist=session['sidlist'],
                    return_sidlist=session['return_sidlist'],
                    interval=session['interval'],
                    auth_mode=session['auth_mode'],
                    sender_key_chain=session['sender_key_chain'],
                    reflector_key_chain=session['reflector_key_chain'],
                    sender_timestamp_format=session['sender_timestamp_format'],
                    reflector_timestamp_format=session['reflector_timestamp_format'],
                    packet_loss_type=session['packet_loss_type'],
                    delay_measurement_mode=session['delay_measurement_mode'],
                    session_reflector_mode=session['session_reflector_mode'],
                    duration=session['duration']
                )
                sess.is_running = session['is_running']
                sess.stamp_session_direct_path_results = STAMPSessionResults(
                    ssid=session['ssid'],
                    store_individual_delays=True)
                sess.stamp_session_return_path_results = STAMPSessionResults(
                    ssid=session['ssid'],
                    store_individual_delays=True)

                sess.stamp_session_direct_path_results.delays = session[
                    'results']['direct_path']['delays']
                sess.stamp_session_direct_path_results.mean_delay = \
                    session['results']['direct_path']['average_delay']
                sess.stamp_session_direct_path_results.count_packets = \
                    session['results']['direct_path']['count_packets']
                sess.stamp_session_direct_path_results.last_result_id = \
                    session['results']['direct_path']['last_result_id']

                sess.stamp_session_return_path_results.delays = \
                    session['results']['return_path']['delays']
                sess.stamp_session_return_path_results.mean_delay = \
                    session['results']['return_path']['average_delay']
                sess.stamp_session_return_path_results.count_packets = \
                    session['results']['return_path']['count_packets']
                sess.stamp_session_return_path_results.last_result_id = \
                    session['results']['return_path']['last_result_id']

                sessions.append(sess)

            if return_dict:
                # Build a dict representation of the STAMP sessions
                res = dict()
                for session in sessions:
                    res[session.ssid] = session
            else:
                res = list(sessions)
            logging.debug('STAMP sessions found: %s' % stamp_sessions)
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return the devices
        return res

    def get_stamp_session(self, ssid, tenantid):
        """
        Get a STAMP session.
        """

        # Build the query
        query = {'ssid': ssid, 'tenantid': tenantid}
        # Find the STAMP session
        logging.debug('Retrieving STAMP session %s' % ssid)
        sess = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP sessions collection
            stamp_sessions = db.stamp_sessions
            # Find the STAMP sessions
            session = stamp_sessions.find_one(query)
            if session is not None:
                sender = self.get_stamp_nodes(
                    node_ids=[session['sender_id']], tenantid=tenantid)[0]
                if session['sender_id'] == session['reflector_id']:
                    reflector = sender
                else:
                    reflector = self.get_stamp_nodes(
                        node_ids=[session['reflector_id']], tenantid=tenantid)[0]

                # Parse session
                sess = STAMPSession(
                    ssid=session['ssid'],
                    description=session['description'],
                    sender=sender,
                    reflector=reflector,
                    sidlist=session['sidlist'],
                    return_sidlist=session['return_sidlist'],
                    interval=session['interval'],
                    auth_mode=session['auth_mode'],
                    sender_key_chain=session['sender_key_chain'],
                    reflector_key_chain=session['reflector_key_chain'],
                    sender_timestamp_format=session['sender_timestamp_format'],
                    reflector_timestamp_format=session['reflector_timestamp_format'],
                    packet_loss_type=session['packet_loss_type'],
                    delay_measurement_mode=session['delay_measurement_mode'],
                    session_reflector_mode=session['session_reflector_mode'],
                    duration=session['duration']
                )
                sess.is_running = session['is_running']
                sess.stamp_session_direct_path_results = STAMPSessionResults(
                    ssid=session['ssid'],
                    store_individual_delays=True)
                sess.stamp_session_return_path_results = STAMPSessionResults(
                    ssid=session['ssid'],
                    store_individual_delays=True)

                sess.stamp_session_direct_path_results.delays = \
                    session['results']['direct_path']['delays']
                sess.stamp_session_direct_path_results.mean_delay = \
                    session['results']['direct_path']['average_delay']
                sess.stamp_session_direct_path_results.count_packets = \
                    session['results']['direct_path']['count_packets']
                sess.stamp_session_direct_path_results.last_result_id = \
                    session['results']['direct_path']['last_result_id']

                sess.stamp_session_return_path_results.delays = \
                    session['results']['return_path']['delays']
                sess.stamp_session_return_path_results.mean_delay = \
                    session['results']['return_path']['average_delay']
                sess.stamp_session_return_path_results.count_packets = \
                    session['results']['return_path']['count_packets']
                sess.stamp_session_return_path_results.last_result_id = \
                    session['results']['return_path']['last_result_id']

            logging.debug('STAMP session found: %s' % session)
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return the device
        return sess

    # Return True if a STAMP session exists,
    # False otherwise

    def stamp_session_exists(self, ssid, tenantid):
        # Build the query
        session = {'ssid': ssid, 'tenantid': tenantid}
        session_exists = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP sessions collection
            stamp_sessions = db.stamp_sessions
            # Count the STAMP sessions with the given SSID
            logging.debug('Searching the STAMP session %s (tenant %s)'
                          % (ssid, tenantid))
            if stamp_sessions.count_documents(session, limit=1):
                logging.debug('The device exists')
                session_exists = True
            else:
                logging.debug('The device does not exist')
                session_exists = False
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return True if the STAMP session exists,
        # False if the STAMP session does not exist
        # or None if an error occurred during the connection to the db
        return session_exists

    # Return True if all the STAMP sessions exist,
    # False otherwise

    def stamp_sessions_exists(self, session_ids):
        # Build the query
        query = {'ssid': {'$in': session_ids}}
        sessions_exist = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP sessions collection
            stamp_sessions = db.stamp_sessions
            # Count the STAMP sessions with the given SSID
            logging.debug('Searching the devices %s' % session_ids)
            if stamp_sessions.count_documents(query) == len(session_ids):
                logging.debug('The STAMP sessions exist')
                sessions_exist = True
            else:
                logging.debug('The STAMP sessions do not exist')
                sessions_exist = False
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return True if the STAMP sessions exist,
        # False if the STAMP sessions do not exist
        # or None if an error occurred during the connection to the db
        return sessions_exist

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
        # Build the query
        query = {'ssid': ssid, 'tenantid': tenantid}
        # Build the update
        update = {'$set': {
            'is_running': is_running
        }
        }
        success = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP Sessions collection
            stamp_sessions = db.stamp_sessions
            # Find the device
            logging.debug('Update STAMP Session running state: %s' %
                          is_running)
            # Get the device
            success = stamp_sessions.update_one(
                query, update).matched_count == 1
            if not success:
                logging.error('Cannot update is_running flag')
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return True if success,
        # False if failure,
        # None if error occurred in connection to the db
        return success

    def create_stamp_node(self, node, tenantid):
        """
        Store a new STAMP Node.
        """

        # Build the document to insert
        node = {
            'node_id': node.node_id,
            'grpc_ip': node.grpc_ip,
            'grpc_port': node.grpc_port,
            'ip': node.ip,
            'node_name': node.node_name,
            'interfaces': node.interfaces,
            'stamp_source_ipv6_address': node.stamp_source_ipv6_address,
            'is_sender_initialized': node.is_sender_initialized,
            'is_reflector_initialized': node.is_reflector_initialized,
            'sender_udp_port': node.sender_udp_port,
            'reflector_udp_port': node.reflector_udp_port,
            'is_sender': node.is_sender,
            'is_reflector': node.is_reflector,
            'sessions_count': node.sessions_count,
            'tenantid': tenantid
        }
        # Register the STAMP node
        logging.debug('Registering STAMP Node on DB: %s' % node)
        success = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP nodes collection
            stamp_nodes = db.stamp_nodes
            # Add the STAMP nodes to the collection
            success = stamp_nodes.insert_one(node).acknowledged
            if success:
                logging.debug('STAMP Node successfully registered')
            else:
                logging.error('Cannot create the STAMP Node')
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return
        return success

    def update_stamp_node(self, node_id, tenantid, grpc_ip=None, grpc_port=None):
        """
        Update an existing STAMP Node.
        """

        # Build the query for the update operation
        query = {
            'node_id': node_id,
            'tenantid': tenantid
        }
        # Build the update
        update = {
            '$set': {}
        }
        if grpc_ip is not None:
            update['$set']['grpc_ip'] = grpc_ip
        if grpc_port is not None:
            update['$set']['grpc_port'] = grpc_port
        # Update the STAMP node
        logging.debug('Updating STAMP Node on DB: %s' % node_id)
        success = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP nodes collection
            stamp_nodes = db.stamp_nodes
            # Update the STAMP node
            success = stamp_nodes.update_one(query, update).matched_count == 1
            if success:
                logging.debug('STAMP Node %s updated registered', node_id)
            else:
                logging.error('Cannot update the STAMP Node')
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return
        return success

    # Remove a STAMP Node

    def remove_stamp_node(self, node_id, tenantid):
        # Build the document to remove
        node = {'node_id': node_id, 'tenantid': tenantid}
        # Remove the node
        logging.debug('Removing STAMP Node: %s (tenant %s)'
                      % (node_id, tenantid))
        success = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP Nodes collection
            stamp_nodes = db.stamp_nodes
            # Delete the STAMP Node from the collection
            success = stamp_nodes.delete_one(node).deleted_count == 1
            if success:
                logging.debug('STAMP Node removed successfully')
            else:
                logging.error('Cannot remove the STAMP Node')
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return
        return success

    # Remove all the STAMP nodes of a tenant

    def remove_stamp_nodes_by_tenantid(self, tenantid):
        # Build the filter
        nodes = {'tenantid': tenantid}
        # Delete all the STAMP nodes in the collection
        logging.debug(
            'Unregistering all the STAMP nodes of the tenant %s' % tenantid)
        success = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP nodes collection
            stamp_nodes = db.stamp_nodes
            success = stamp_nodes.delete_many(nodes).acknowledged
            if success:
                logging.debug('Devices successfully unregistered')
            else:
                logging.error('Cannot remove the STAMP nodes')
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return
        return success

    # Remove all the STAMP nodes

    def remove_all_stamp_nodes(self):
        # Delete all the STAMP nodes in the collection
        logging.debug('Removing all the STAMP nodes')
        success = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP nodes collection
            stamp_nodes = db.stamp_nodes
            success = stamp_nodes.delete_many().acknowledged
            if success:
                logging.debug('STAMP nodes successfully removed')
            else:
                logging.error('Cannot remove the STAMP nodes')
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return
        return success

    def get_stamp_nodes(self, node_ids=None, tenantid=None, return_dict=False):
        """
        Get STAMP nodes."""

        # Build the query
        query = dict()
        if tenantid is not None:
            query['tenantid'] = tenantid
        if node_ids is not None:
            query['node_id'] = {'$in': list(node_ids)}
        # Find the STAMP node by SSID
        logging.debug('Retrieving STAMP nodes [%s] by tenant ID %s' % (
            node_ids, tenantid))
        res = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP nodes collection
            stamp_nodes = db.stamp_nodes
            # Find the STAMP nodes
            _stamp_nodes = stamp_nodes.find(query)
            stamp_nodes = []
            for _node in _stamp_nodes:
                node = STAMPNode(
                    node_id=_node.get('node_id'),
                    grpc_ip=_node.get('grpc_ip'),
                    grpc_port=_node.get('grpc_port'),
                    ip=_node.get('ip'),
                    node_name=_node.get('node_name'),
                    interfaces=_node.get('interfaces'),
                    stamp_source_ipv6_address=_node.get(
                        'stamp_source_ipv6_address'),
                    is_sender=_node.get('is_sender'),
                    is_reflector=_node.get('is_reflector'),
                    sender_udp_port=_node.get('sender_udp_port'),
                    reflector_udp_port=_node.get('reflector_udp_port')
                )
                node.is_sender_initialized = _node.get('is_sender_initialized')
                node.is_reflector_initialized = _node.get(
                    'is_reflector_initialized')
                node.sessions_count = _node.get('sessions_count')
                stamp_nodes.append(node)
            if return_dict:
                # Build a dict representation of the STAMP nodes
                res = dict()
                for node in stamp_nodes:
                    ssid = node['node_id']
                    res[ssid] = node
            else:
                res = list(stamp_nodes)
            logging.debug('STAMP nodes found: %s' % stamp_nodes)
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return the devices
        return res

    def get_stamp_node(self, node_id, tenantid):
        """
        Get a STAMP node.
        """

        # Build the query
        query = {'node_id': node_id, 'tenantid': tenantid}
        # Find the STAMP node
        logging.debug('Retrieving STAMP node %s' % node_id)
        node = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP nodes collection
            stamp_nodes = db.stamp_nodes
            # Find the STAMP nodes
            _node = stamp_nodes.find_one(query)
            if _node is not None:
                node = STAMPNode(
                    node_id=_node.get('node_id'),
                    grpc_ip=_node.get('grpc_ip'),
                    grpc_port=_node.get('grpc_port'),
                    ip=_node.get('ip'),
                    node_name=_node.get('node_name'),
                    interfaces=_node.get('interfaces'),
                    stamp_source_ipv6_address=_node.get(
                        'stamp_source_ipv6_address'),
                    is_sender=_node.get('is_sender'),
                    is_reflector=_node.get('is_reflector'),
                    sender_udp_port=_node.get('sender_udp_port'),
                    reflector_udp_port=_node.get('reflector_udp_port')
                )
                node.is_sender_initialized = _node.get('is_sender_initialized')
                node.is_reflector_initialized = _node.get(
                    'is_reflector_initialized')
                node.sessions_count = _node.get('sessions_count')
            logging.debug('STAMP node found: %s' % node)
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return the device
        return node

    def set_sender_inizialized(self, node_id, tenantid, is_initialized=True):
        # Build the query
        query = {'node_id': node_id, 'tenantid': tenantid}
        # Build the update
        update = {'$set': {
            'is_sender_initialized': is_initialized
        }
        }
        success = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP Sessions collection
            stamp_nodes = db.stamp_nodes
            # Find the device
            logging.debug('Update STAMP Node initialized: %s' % is_initialized)
            # Get the device
            success = stamp_nodes.update_one(
                query, update).matched_count == 1
            if not success:
                logging.error('Cannot update initialized flag')
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return True if success,
        # False if failure,
        # None if error occurred in connection to the db
        return success

    def set_reflector_inizialized(self, node_id, tenantid,
                                  is_initialized=True):
        # Build the query
        query = {'node_id': node_id, 'tenantid': tenantid}
        # Build the update
        update = {'$set': {
            'is_reflector_initialized': is_initialized
        }
        }
        success = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP Sessions collection
            stamp_nodes = db.stamp_nodes
            # Find the device
            logging.debug('Update STAMP Node initialized: %s' % is_initialized)
            # Get the device
            success = stamp_nodes.update_one(
                query, update).matched_count == 1
            if not success:
                logging.error('Cannot update initialized flag')
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return True if success,
        # False if failure,
        # None if error occurred in connection to the db
        return success

    # Return True if a STAMP node exists,
    # False otherwise

    def stamp_node_exists(self, node_id, tenantid):
        # Build the query
        node = {'node_id': node_id, 'tenantid': tenantid}
        node_exists = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP nodes collection
            stamp_nodes = db.stamp_nodes
            # Count the STAMP nodes with the given SSID
            logging.debug('Searching the STAMP node %s (tenant %s)'
                          % (node_id, tenantid))
            if stamp_nodes.count_documents(node, limit=1):
                logging.debug('The device exists')
                node_exists = True
            else:
                logging.debug('The device does not exist')
                node_exists = False
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return True if the STAMP node exists,
        # False if the STAMP node does not exist
        # or None if an error occurred during the connection to the db
        return node_exists

    # Return True if all the STAMP nodes exist,
    # False otherwise

    def stamp_nodes_exists(self, node_ids):
        # Build the query
        query = {'node_id': {'$in': node_ids}}
        nodes_exist = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP nodes collection
            stamp_nodes = db.stamp_nodes
            # Count the STAMP nodes with the given SSID
            logging.debug('Searching the devices %s' % node_ids)
            if stamp_nodes.count_documents(query) == len(node_ids):
                logging.debug('The STAMP nodes exist')
                nodes_exist = True
            else:
                logging.debug('The STAMP nodes do not exist')
                nodes_exist = False
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return True if the STAMP nodes exist,
        # False if the STAMP nodes do not exist
        # or None if an error occurred during the connection to the db
        return nodes_exist

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
        # Build the query
        query = {'ssid': ssid, 'tenantid': tenantid}
        success = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP Sessions collection
            stamp_sessions = db.stamp_sessions
            # Find the device
            logging.debug('Update STAMP Session %s mean delay, direction %s'
                          % (ssid, direction))
            logging.debug('New mean delay: %s' % mean_delay)
            # Get the device
            stamp_session = stamp_sessions.find_one(query)
            if stamp_session is None:
                logging.error('Cannot retrieve STAMP session')
            results = stamp_session['results']
            results[direction]['average_delay'] = mean_delay
            # Build the update
            update = {'$set': {
                'results': results
            }
            }
            # Get the device
            success = stamp_sessions.update_one(
                query, update).matched_count == 1
            if not success:
                logging.error('Cannot update mean delay')
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return True if success,
        # False if failure,
        # None if error occurred in connection to the db
        return success

    def add_delay(self, ssid, tenantid, new_delay, direction='direct_path'):
        counter = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP Sessions collection
            stamp_sessions = db.stamp_sessions
            # Find the device
            logging.debug('Getting the STAMP Session %s (tenant %s)'
                          % (ssid, tenantid))
            # Build query
            query = {'ssid': ssid,
                     'tenantid': tenantid}
            # Find the STAMP sessions
            stamp_session = stamp_sessions.find_one(query)
            # Get last result ID
            last_result_id = stamp_session['results'][direction]['last_result_id']
            # Increase last result ID
            last_result_id += 1
            # Build the update
            update = {'$push': {
                'results.' + direction + '.delays': {
                    'id': last_result_id,
                    'value': new_delay,
                    'timestamp': time.time()}}
            }
            # If the counter does not exist, create it
            stamp_sessions.update_one(query, update)
            # Update last result ID
            update = {'$inc': {'results.' + direction + '.last_result_id': 1}}
            stamp_sessions.update_one(query, update)
            # Build the query
            query = {'ssid': ssid,
                     'tenantid': tenantid}
            # Build the update
            update = {'$inc': {'results.' + direction + '.count_packets': 1}}
            # Increase the STAMP packets counter for the Session
            session = stamp_sessions.find_one_and_update(
                query, update)
            # Return the counter if exists, 0 otherwise
            counter = session['results'][direction]['count_packets']
            logging.debug('Counter before the increment: %s' % counter)
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return the counter if success,
        # None if an error occurred during the connection to the db
        return counter

    def get_mean_delay(self, ssid, tenantid, direction='direct_path'):
        # Build the query
        query = {'ssid': ssid, 'tenantid': tenantid}
        # Find the average delay
        logging.debug('Retrieving average delay ssid %s', ssid)
        average_delay = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP sessions collection
            stamp_sessions = db.stamp_sessions
            # Find the STAMP session
            session = stamp_sessions.find_one(query)
            if session is not None:
                average_delay = session['results'][direction]['average_delay']
            logging.debug('Average delay: %s' % average_delay)
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return the average delay
        return average_delay

    def get_count_packets(self, ssid, tenantid, direction='direct_path'):
        # Build the query
        query = {'ssid': ssid, 'tenantid': tenantid}
        # Find the STAMP node
        logging.debug('Retrieving count packets ssid %s', ssid)
        count_packets = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP sessions collection
            stamp_sessions = db.stamp_sessions
            # Find the STAMP sessions
            session = stamp_sessions.find_one(query)
            if session is not None:
                count_packets = session['results'][direction]['count_packets']
            logging.debug('Packets count: %s' % count_packets)
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return the device
        return count_packets

    def add_delay_and_update_average(self, ssid, tenantid, new_delay,
                                     direction='direct_path'):
        self.add_delay(ssid=ssid, tenantid=tenantid, new_delay=new_delay,
                       direction=direction)
        mean_delay = self.get_mean_delay(ssid=ssid, tenantid=tenantid,
                                         direction=direction)
        count_packets = self.get_count_packets(ssid=ssid, tenantid=tenantid,
                                               direction=direction)
        new_mean_delay = compute_mean_delay_welford(
            current_mean_delay=mean_delay,
            count=count_packets, new_delay=new_delay)
        self.set_mean_delay(ssid=ssid, tenantid=tenantid, mean_delay=new_mean_delay,
                            direction=direction)

    def increase_sessions_count(self, node_id, tenantid):
        counter = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP nodes collection
            stamp_nodes = db.stamp_nodes
            # Find the STAMP node
            logging.debug('Getting the STAMP Node %s (tenant %s)'
                          % (node_id, tenantid))
            # Build query
            query = {'node_id': node_id,
                     'tenantid': tenantid}
            # Build the update
            update = {'$inc': {'sessions_count': 1}}
            # Increase the STAMP sessions counter for the STAMP node
            session = stamp_nodes.find_one_and_update(
                query, update)
            # Return the counter if exists, 0 otherwise
            counter = session['sessions_count']
            logging.debug('Counter before the increment: %s' % counter)
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return the counter if success,
        # None if an error occurred during the connection to the db
        return counter

    def decrease_sessions_count(self, node_id, tenantid):
        counter = None
        try:
            # Get a reference to the MongoDB client
            client = self.get_mongodb_session()
            # Get the database
            db = client.EveryWan
            # Get the STAMP nodes collection
            stamp_nodes = db.stamp_nodes
            # Find the STAMP node
            logging.debug('Getting the STAMP Node %s (tenant %s)'
                          % (node_id, tenantid))
            # Build query
            query = {'node_id': node_id,
                     'tenantid': tenantid}
            # Build the update
            update = {'$inc': {'sessions_count': -1}}
            # decrease the STAMP sessions counter for the STAMP node
            session = stamp_nodes.find_one_and_update(
                query, update)
            # Return the counter if exists, 0 otherwise
            counter = session['sessions_count']
            logging.debug('Counter before the decrement: %s' % counter)
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return the counter if success,
        # None if an error occurred during the connection to the db
        return counter

    def get_new_ssid(self, tenantid):
        """
        Allocate and return a new SSID for a STAMP Session.
        """

        # Get a reference to the MongoDB client
        client = self.get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the tenants collection
        tenants = db.tenants
        # Get a new SSID
        ssid = None
        logging.debug('Getting new SSID for the tenant %s' % tenantid)
        try:
            # Build the query
            query = {'tenantid': tenantid}
            # Check if a reusable table ID is available
            tenant = tenants.find_one(query)
            if tenant is None:
                logging.debug('The tenant does not exist')
            else:
                reusable_ssid = tenant['counters']['ssid']['reusable_ssid']
                if len(reusable_ssid) > 0:
                    # Get a SSID
                    ssid = reusable_ssid.pop()
                    # Remove the SSID from the reusable_ssid list
                    update = {
                        '$set': {'counters.ssid.reusable_ssid': reusable_ssid}}
                    if tenants.update_one(query, update).modified_count != 1:
                        logging.error(
                            'Error while updating reusable table IDs list')
                else:
                    # No reusable ID, allocate a new table ID
                    tenant = tenants.find_one(query)
                    if tenantid is not None:
                        ssid = tenant['counters']['ssid']['last_ssid']
                        while True:
                            ssid += 1
                            if ssid not in RESERVED_SSID:
                                logging.debug('Found SSID: %s' % ssid)
                                break
                            logging.debug(
                                'SSID %s is reserved. Getting new SSID' % ssid)
                    else:
                        logging.error('Error in get_new_tableid')
                    update = {
                        '$set': {'counters.ssid.last_ssid': ssid}}
                    if tenants.update_one(query, update).modified_count != 1:
                        logging.error(
                            'Error while updating last_ssid')
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return the SSID
        return ssid

    def release_ssid(self, ssid, tenantid):
        """
        Release a SSID and mark it as reusable.
        """

        # Build the query
        query = {'tenantid': tenantid}
        # Get a reference to the MongoDB client
        client = self.get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the tenants collection
        tenants = db.tenants
        # Release the SSID
        logging.debug('Release SSID %s, tenant %s' % (ssid, tenantid))
        success = None
        try:
            # Get the tenant
            tenant = tenants.find_one(query)
            if tenant is None:
                logging.debug('The tenant does not exist')
            else:
                reusable_ssid = tenant['counters']['ssid']['reusable_ssid']
                # Add the SSID to the reusable SSIDs list
                reusable_ssid.append(ssid)
                update = {
                    '$set': {'counters.ssid.reusable_ssid': reusable_ssid}}
                if tenants.update_one(query, update).modified_count != 1:
                    logging.error(
                        'Error while updating reusable table IDs list')
                    success = False
                else:
                    logging.debug(
                        'Table ID added to reusable_tableids list')
                    success = True
        except pymongo.errors.ServerSelectionTimeoutError:
            logging.error('Cannot establish a connection to the db')
        # Return True if success,
        # False if failure,
        # None if an error occurred during the connection to the db
        return success
