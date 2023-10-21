import getopt
import ipaddress
import os
import queue
import socket
import sys
import constants
import importlib


def parse_arguments():
    # Initialization
    print(constants.OPENING_BANNER)
    source_ip, source_port = "", ""

    # GetOpt Arguments
    arguments = sys.argv[1:]
    opts, user_list_args = getopt.getopt(arguments, 's:p:')

    if len(opts) == constants.ZERO:
        sys.exit(constants.NO_ARG_ERROR)

    for opt, argument in opts:
        if opt == '-s':  # For source IP
            try:
                if argument == constants.LOCAL_HOST:
                    argument = constants.LOCAL_HOST_VALUE
                source_ip = str(ipaddress.ip_address(argument))
            except ValueError as e:
                sys.exit(constants.INVALID_SRC_IP_ADDRESS_ARG_ERROR.format(e))

        if opt == '-p':  # For source port
            try:
                source_port = int(argument)
                if not (constants.MIN_PORT_RANGE < source_port < constants.MAX_PORT_RANGE):
                    sys.exit(constants.INVALID_SRC_PORT_NUMBER_RANGE)
            except ValueError as e:
                sys.exit(constants.INVALID_FORMAT_SRC_PORT_NUMBER_ARG_ERROR.format(e))

    # Check if IPs and Ports were specified
    if len(source_ip) == constants.ZERO:
        sys.exit(constants.NO_SRC_IP_ADDRESS_SPECIFIED_ERROR)

    if len(str(source_port)) == constants.ZERO:
        sys.exit(constants.NO_SRC_PORT_NUMBER_SPECIFIED_ERROR)

    return source_ip, source_port


def initialize_server_socket(source_ip: str, source_port: int):
    """

    :param source_ip:
    :param source_port:
    :return:
    """
    try:
        # Create a socket object
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Define the server address and port
        server_address = (source_ip, source_port)

        # Bind the socket to the server address and port
        server_socket.bind(server_address)

        # Listen for incoming connections (maximum 5 clients in the queue)
        server_socket.listen(5)
        print(constants.SUCCESS_SOCKET_CREATE_MSG)
        print(constants.SOCKET_INFO_MSG.format(*server_address))

    except PermissionError as e:
        sys.exit(constants.VICTIM_SERVER_SOCKET_CREATION_ERROR_MSG.format(str(e)))

    return server_socket


def is_file_openable(file_path):
    try:
        with open(file_path, constants.READ_MODE) as file:
            pass
        return True
    except IOError as e:
        print(constants.FILE_CANNOT_OPEN_ERROR.format(file_path, e))
        return False


def is_importable(file_name: str):
    print(f"[+] Importing module {file_name}...")

    try:
        importlib.import_module(file_name)
        return True
    except ImportError as e:
        print(constants.FAILED_IMPORT_ERROR.format(file_name, e))
        return False
    except Exception as e:
        print(constants.FAILED_IMPORT_EXCEPTION_ERROR.format(file_name, e))
        return False


def watch_stop_signal(client_socket: socket.socket, signal_queue: queue.Queue):
    while True:
        try:
            signal = client_socket.recv(100).decode()
            if signal == "STOP":
                print(constants.CLIENT_RESPONSE.format(signal))
                signal_queue.put(signal)
                return None
        except socket.timeout as e:
            print("[+] ERROR: Connection to client has timed out : {}".format(e))
            break
        except socket.error as e:
            print("[+] Socket error: {}".format(e))
            break


def delete_file(file_path: str):
    try:
        if os.path.exists(file_path):
            print(f"[+] OPERATION PENDING: Now deleting {file_path}...")
            os.remove(file_path)
            print(f"[+] OPERATION SUCCESS: {file_path} has been successfully deleted!")
        else:
            print(f"[+] NO ACTION REQUIRED: {file_path} does not exist!")
    except FileNotFoundError:
        print(f"[+] ERROR: The file '{file_path}' does not exist or cannot be deleted.")
    except Exception as e:
        print(f"[+] ERROR: An error occurred while deleting the file: {e}")
