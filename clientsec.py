#!/usr/bin/python3
import msgpack
import hmac
import hashlib
import json
import socket
import hashlib
from os.path import expanduser

# PARAMETERS
max_nb_attempts = 5 # stop after max_nb_attempts unanswered auth requests
reception_timeout = 2 # wait up to reception_timeout sec for the response, if no answers are received in that time resend it by changing ctr
# Service for which authentication is asked 
server_ip = '10.0.0.2'
server_port = 22
conf_path = conf_path = expanduser("~")+'/conf.json'
transport_layer = 'tcp'

# Generate and returns an auth request ready to be sent
def make_auth_request(server_ip, server_port, ctr, transport_layer, client_ip, shared_key):
    # json request
    request_data_dict = {
      'server': server_ip,
      'dport': server_port,
      'ctr': ctr,
      'tcp_udp' : transport_layer,
      'my_ip': client_ip, 
      'hmac': 0
    }

    # Serialize request_data_dict
    request_data_raw = msgpack.packb(request_data_dict)

    # Generate a message authentication code of request_data_raw based on 
    # the shared_key and secure hashing algorithm SHA256 using hmac module
    hmac1 = hmac.new(key=shared_key.digest(), digestmod=hashlib.sha256)
    hmac1.update(request_data_raw)
    message_digest = hmac1.digest()
    
    # Insert the computed HMAC in hmac value of the request dictionary
    request_data_dict['hmac'] = message_digest
    
    # Serialize request_data_dict with the updated HMAC
    auth_request = msgpack.packb(request_data_dict)
    
    return auth_request

# Given the an auth request/reply message returns True if it is authenticated
def is_msg_authenticated(rcv_message, hash_key):

    #rcv_message = json.load(rcv_message)
    rcv_hmac = rcv_message['hmac']

    # Compute the HMAC of the modified authentication request (hmac=0)
    rcv_message['hmac'] = 0
    modified_json = msgpack.packb(rcv_message)
    computed_hmac = hmac.new(key=hash_key.digest(), digestmod=hashlib.sha256)
    computed_hmac.update(modified_json)
    message_digest = computed_hmac.digest()

    # Compare the computed HMAC with the received one
    return hmac.compare_digest(rcv_hmac, message_digest)


# Read conf.json to retrieve parameters to perform the authentication request
with open(conf_path, 'r') as config_file:
    config_json = json.load(config_file)
    controller_ip = config_json["controller_ip"]
    auth_port = config_json["auth_port"]
    master_key = config_json["master_key"]
    ctr = config_json["next_ctr"]

# Get the two symmetric keys from the master key for HMAC generation
my_shared_key = hashlib.sha256(str.encode(str(master_key+'0')))
controller_shared_key = hashlib.sha256(str.encode(str(master_key+'1')))
print("Obtained the following shared keys:\n\tclient {}\n\tcontroller {}".format(my_shared_key.hexdigest(), controller_shared_key.hexdigest()))

# Retrieve my ip -> required later for auth request
# local_ip = socket.gethostbyname(socket.gethostname()) # does not work on mininet
local_ip = '10.0.0.1' # needed in 

# --- Perform the authentication request ---
has_srv_replied = False
nb_attempts = 0
authorised_by_controller = False

while (not authorised_by_controller) and (nb_attempts < max_nb_attempts):
    # Generate auth request
    auth_request = make_auth_request(server_ip, server_port, ctr, transport_layer, local_ip, my_shared_key)
    # Use socket to send the auth request and retrieve the auth reply from controller
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.settimeout(reception_timeout)
    sock.sendto(auth_request, (controller_ip, auth_port))
    nb_attempts += 1
    print("Authentication request sent with counter {}".format(ctr))
    try:
        rcv_message, rcv_address = sock.recvfrom(1024)
        rcv_ip = rcv_address[0]

        rcv_message = msgpack.unpackb(rcv_message)

        #rcv_message = rcv_message[Raw].load
        # Accept responses only from controller IP
        if rcv_ip == controller_ip:
            # check authentication
            if is_msg_authenticated(rcv_message, controller_shared_key):
                has_srv_replied = True
                # check if controller granted the authentication
                unpacked_auth_reply = rcv_message
                print('\tController replied with {}'.format(unpacked_auth_reply['code']))
                if unpacked_auth_reply['code'] == "202 Authentication Accepted":
                    authorised_by_controller = True
                    # Update ctr
                    ctr = unpacked_auth_reply['expected_ctr']
                elif unpacked_auth_reply['code'] == "449 Retry With":
                    if max_nb_attempts < 16:
                        print('\tUpdating counter to {} and increasing max_nb_attempts value'.format(unpacked_auth_reply['expected_ctr']))
                        ctr = unpacked_auth_reply['expected_ctr']
                        max_nb_attempts = max_nb_attempts + nb_attempts

            else:
                print('Received a non authenticated message from controller IP')
                ctr += 1            
        else:
            print("\tReceived a packet but not from controller ({})".format(rcv_ip))
    except socket.timeout:
        print("\tReply not received from controller")
        ctr += 1 # Should we increase the counter here?
        continue

# Once the authentication phase has been completed successfully, close the socket
sock.close()

# In case of no answer from controller or no authorization -> stop here
if not has_srv_replied:
    print('*** Unable to reach the controller after {} attempts. Try later ***'.format(max_nb_attempts))
    exit()
elif not authorised_by_controller:
    print('*** Not authorized by controller ***'.format(max_nb_attempts))
    exit()
    
# --- Update next_ctr value in config.json ---
with open(conf_path, 'r') as config_file:
    config_json = json.load(config_file)

config_json["next_ctr"] = ctr

with open(conf_path, 'w') as config_file:
    json.dump(config_json, config_file)
    
# OPEN SOCKET WITH SERVER TCP

print('Starting TCP connection with server...')
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSocket.connect((server_ip, server_port))

msg = 'Hello server! Finally I can talk with you'
clientSocket.send(msg)

resp = clientSocket.recv(1024)
print('Received message:'+ resp)

clientSocket.close()