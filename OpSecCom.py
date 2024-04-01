from collections import namedtuple
from typing import Final
from scapy.all import *
import random
import time
import re
import hashlib
import math
import sys

#########################
######### Setup #########
#########################
# Select interface for listening/sending
detected_interfaces = list(conf.ifaces.keys())
monitor_mode_regex = re.compile(r'wlan(\d)mon') # Searching for 'wlan' + # + 'mon' format
valid_interfaces = list(filter(monitor_mode_regex.search, detected_interfaces))

if len(valid_interfaces) == 0:
    print('Error: could not find a likely monitor mode interface')
    sys.exit()
else:
    if len(valid_interfaces) > 1:
        print(f'INFO: Multiple Monitor mode wlan interfaces detected, choosing {valid_interfaces[0]}')
    conf.iface = valid_interfaces[0]

# Filter out non-Dot11 traffic
if not conf.layers.filtered:
    conf.layers.filter([Dot11])

# Set seed for reproducibility
random.seed(1)  

print('OSC2 Setup')

######################
###### Constants #####
######################
# BPF Filters used to limit received frames to 802.11 control rts/cts
RTSCTS_FILTER: Final[str] = "wlan type ctl subtype rts or wlan type ctl subtype cts"
RTS_FILTER: Final[str] = "wlan type ctl subtype rts"
CTS_FILTER: Final[str] = "wlan type ctl subtype cts"

# Constants for frame type/subtype
CONTROL: Final[int] = 1
RTS: Final[int] = 11
CTS: Final[int] = 12

######################
# OpSecCom Constants #
######################
MAC_BITS: Final[int]                    = 0x02              # The header that is always used in OSC
HEADER_MASK: Final[int]                 = 0xfc0000000000    # Bit mask for isolating the header
ID_MASK: Final[int]                     = 0x00ff00000000    # Bit mask for isolating the pkt id of an OSC frame
PAYLOAD_MASK: Final[int]                = 0x0000ffffffff    # Bit mask for isolating the payload of an OSC frame
DEFAULT_STATE_NORMAL: Final[int]        = 0x11111111        # A default payload for the normal state. In use should be randomized
DEFAULT_STATE_ALERT: Final[int]         = 0x99999999        # A default payload for the alert state. In use should be randomized
DEFAULT_CHALLENGE_SEQ: Final[int]       = 0xcccccccc        # A default payload for the challenge sequence. In use should be randomized
OSC_REQ_SEQ: Final[int]                 = 0x00000000        # A default payload for requesting a canary. In use should be randomized
ERROR: Final[int]                       = 0xeeeeeeee        # A default payload for communicating an error. In use should be randomized

######################
##### Properties #####
######################
# Note these are globally accessed

# General properties
normal_state = 0        # The agreed upon identifier for the normal state
alert_state = 0         # The agreed upon identifier for the alert state
challenge_seq = 0       # The agreed upon identifier for the challenge sequence
seen_osc_messages = []  # List of OSC messages seen, used to avoid responding to duplicate frames

# Canary properties
canary_mac = '02:02:03:04:05:06'    # Mac address of canary device
current_status_fine   = True        # Flag for whether node is compromised
setup_state = 0                     # 0: not setup, 1: first assoc msg received and response sent, 2: setup
setup_id = 0                        # The id of the frame that sent the OSC_REQ_SEQ. This id is used for both messages setting up a OSC connection

# Watcher properties
outstanding_message_id = ''         # ID of the active outgoing message
mac_as_sent = ''                    # The MAC as we sent it, so we can check if a response to OSC RTS is just parroting back the MAC


#########################
### General functions ###
#########################
# Int <-> Hex conversions
def intToHex(numb: int) -> str:
    return hex(numb)[2:]

def hexToInt(hexString: str) -> int:
    return int(hexString, 16)

# MAC <-> Int conversions
def intToMac(numb: int) -> str:
    temp = intToHex(numb)
    temp = '0' * (12 - len(temp)) + temp # Pad front as many as necessary
    temp = ':'.join(temp[i:i+2] for i in range(0, len(temp), 2))
    return temp

def macToInt(mac: str) -> int:
    return hexToInt(mac.replace(':', ''))

# Testers
def toMe(dot11_pkt: Dot11) -> bool:
    return dot11_pkt.addr1 == canary_mac

def isRTS(dot11_pkt: Dot11) -> bool:
    return dot11_pkt.subtype == RTS

def isCTS(dot11_pkt: Dot11) -> bool:
    return dot11_pkt.subtype == CTS

def hasOSCHeader(dot11_pkt: Dot11) -> bool:
    pkt_header, pkt_id, pkt_payload = OSC_ExtractParts(dot11_pkt)
    body_hash = calcBodyHash(pkt_id, pkt_payload)
    return pkt_header ^ body_hash == 0                  # Bitwise check that the header matches the hash of the body
    
# Operators
def generateHeader(pkt_id: int, pkt_payload: int) -> int:
    h = calcBodyHash(pkt_id, pkt_payload)
    return h | MAC_BITS         # Combine hash with u/l u/m bits

def calcBodyHash(pkt_id: int, pkt_payload: int) -> bool:
    return calcHash(pkt_id + pkt_payload, 6) << 2  # Get hash and shift two bits left to accomodate the MAC_BITS

def calcHash(data: int, desired_bits: int) -> int:
    hash_length_bytes = math.ceil(desired_bits / 8)
    hash_length_bits = 8 * hash_length_bytes
    encoded = str(data).encode(encoding='UTF-8')
    hex_hash = hashlib.shake_128(encoded).hexdigest(hash_length_bytes)
    int_hash = hexToInt(hex_hash)
    return int_hash >> (hash_length_bits - desired_bits)    # Right shift to reach desired amount of bits

def combineOSCParts(pkt_header: int, pkt_id: int, pkt_payload: int) -> int:
    return (pkt_header << 40) | (pkt_id << 32) | pkt_payload

def OSC_ExtractHeader(dot11_pkt: Dot11) -> int:
    pkt_header, _, _ = OSC_ExtractParts(dot11_pkt)
    return pkt_header

def OSC_ExtractId(dot11_pkt: Dot11) -> int:
    _, pkt_id, _ = OSC_ExtractParts(dot11_pkt)
    return pkt_id

def OSC_ExtractPayload(dot11_pkt: Dot11) -> int:
    _, _, pkt_payload = OSC_ExtractParts(dot11_pkt)
    return pkt_payload

def OSC_ExtractParts(dot11_pkt: Dot11) -> list[int]:
    if isRTS(dot11_pkt):
        return extractOSCPartsFromMac(dot11_pkt.addr2)
    elif isCTS(dot11_pkt):
        return extractOSCPartsFromMac(dot11_pkt.addr1)
    else:
        print('Issue in OSC_ExtractParts: passed packet is neither of RTS/CTS')
        return None

def extractOSCPartsFromMac(mac: str) -> list[int]:
    mac_int = macToInt(mac)
    return payloadExtractOSCParts(mac_int)

def payloadExtractOSCParts(data: int) -> list[int]:
    pkt_header = (data & HEADER_MASK) >> 40
    pkt_id = (data & ID_MASK) >> 32
    pkt_payload = data & PAYLOAD_MASK

    return pkt_header, pkt_id, pkt_payload

def sendDot11(dot11_pkt: Dot11):
    sendp(RadioTap()/dot11_pkt)


#########################
######## Watcher ########
#########################
def runTest():
    global canary_mac

    watcherSetupOSC(canary_mac)

    time.sleep(10)

    queryCanaryStatus(canary_mac)

    time.sleep(10)

    queryCanaryStatus(canary_mac)

def runDataTest():
    global canary_mac

    data = 943934

    pkt_id = generateOSC_ID() # Persist id throughout setup

    print(f'Sending payload: {data}')
    response = sendAndRec(canary_mac, payload=data, id=pkt_id)

    if len(response) == 0: 
        print("Got no response to data message")
        return
    
    dot11_pkt = response[0][Dot11]
    received_data = OSC_ExtractPayload(dot11_pkt)

    print(f'Received back: {received_data}')

def runDataEnduranceTest():
    global canary_mac
    attempts = 0
    succ = 0
    
    with open('data-endurance.txt', 'w') as file:
        for i in range(100):
            data = random.randrange(4294967295)

            pkt_id = generateOSC_ID() # Persist id throughout setup

            print(f'Sending payload: {data}')
            response = sendAndRec(canary_mac, payload=data, id=pkt_id)

            if len(response) == 0: 
                print("Got no response to data message")
                attempts += 1
                file.write(f'Fail: no response')
                continue
            
            dot11_pkt = response[0][Dot11]
            received_data = OSC_ExtractPayload(dot11_pkt)

            print(f'Received back: {received_data}')
            print()

            file.write(f'{data} -> {received_data}: {"Success" if data == received_data else "Fail"}')
            attempts += 1
            succ += 1 if data == received_data else 0

            time.sleep(2)
    
    print(f'Attempts: {attempts}')
    print(f'Success: {succ}')
    print(f'Succ Rate: {succ / attempts}')


# Watcher sends req, canary sends normal state
# Watcher sends challenge seq, canary sends alert state
def watcherSetupOSC(canary_mac: str):
    global normal_state
    global alert_state
    global challenge_seq

    pkt_id = generateOSC_ID() # Persist id throughout setup

    response = sendAndRec(canary_mac, payload=OSC_REQ_SEQ, id=pkt_id)

    if len(response) == 0: 
        print("Got no response to first setup message")
        return
    
    dot11_pkt = response[0][Dot11]              
    normal_state = OSC_ExtractPayload(dot11_pkt)
    print(f'Setup: sent req and received normal state of [{normal_state}]')

    time.sleep(5)

    challenge_seq = DEFAULT_CHALLENGE_SEQ 
    response = sendAndRec(canary_mac, payload=DEFAULT_CHALLENGE_SEQ, id=pkt_id)

    if len(response) == 0: 
        print("Got no response to second setup message")
        return

    dot11_pkt = response[0][Dot11]              
    alert_state = OSC_ExtractPayload(dot11_pkt)
    print(f'Setup: sent challenge seq [{challenge_seq}] and received alert state of [{alert_state}]')

    return

def queryCanaryStatus(canary_mac: str):
    global challenge_seq

    print(f'Querying canary [{canary_mac}] with challenge seq [{challenge_seq}]')
    response = sendAndRec(canary_mac, payload=challenge_seq)

    if len(response) == 0:
        print('ERROR: no response heard')
        return

    print('Response received')

    dot11_pkt = response[0][Dot11]

    response_payload = OSC_ExtractPayload(dot11_pkt)

    print(f'Response payload: {response_payload}')
    if response_payload == normal_state:
        print('State: Normal')
    elif response_payload == alert_state:
        print('State: Alert')
    else:
        print('State: Invalid')

def sendAndRec(canary_mac: str, payload: int, id: int = None) -> Dot11:
    global mac_as_sent
    global outstanding_message_id

    # Create packet and send
    pkt_id = id if id != None else generateOSC_ID()
    pkt = generateOSC_RTS(canary_mac, pkt_id, payload)

    mac_as_sent = pkt.addr2
    outstanding_message_id = pkt_id
    
    sendDot11(pkt)

    response = listenForResponse(pkt_id, mac_as_sent)
    mac_as_sent = ''
    outstanding_message_id = ''

    return response

def generateOSC_RTS(ra: str, pkt_id: int, payload: int) -> Dot11:
    rts_ta = combineOSCParts(generateHeader(pkt_id, payload), pkt_id, payload)
    rts_ta_mac = intToMac(rts_ta) 
    pkt = Dot11(type=CONTROL, subtype=RTS, addr1=ra, addr2=rts_ta_mac)
    return pkt

def generateOSC_ID() -> int:
    return random.getrandbits(8)

def getChallengeSequence() -> int:
    return DEFAULT_CHALLENGE_SEQ

def listenForResponse(osc_id: int, mac_as_sent: str, timeout: int = 60) -> list[Packet]:
    return sniff(lfilter= lambda pkt: filterResponse(pkt), stop_filter= lambda pkt: macMirroredBack(pkt, mac_as_sent), filter=CTS_FILTER, timeout=timeout, count=1)

# If we get back a response with the same mac as we sent out, then that node is not actually OSC
def macMirroredBack(pkt: Packet, original_mac: str) -> bool:
    if not pkt.haslayer(Dot11):
        return False
    dot11_pkt = pkt[Dot11]

    return dot11_pkt.addr1 == original_mac

def filterResponse(pkt: Packet) -> bool:
    if not pkt.haslayer(Dot11):
        return False
    dot11_pkt = pkt[Dot11]

    if not hasOSCHeader(dot11_pkt):
        return False

    pkt_header, pkt_id, payload = OSC_ExtractParts(dot11_pkt)
    tmp = combineOSCParts(pkt_header, pkt_id, payload)
    if tmp in seen_osc_messages:
        return False

    seen_osc_messages.append(tmp)
    
    return isResponseToUs(dot11_pkt)

def isResponseToUs(dot11_pkt: Dot11) -> bool:
    global outstanding_message_id
    return OSC_ExtractId(dot11_pkt) == outstanding_message_id
    




#########################
######## Canary #########
#########################
def runReceiver(capture_limit: int = 1000):
    sniff(lfilter=lambda pkt: likelyOSC, prn=respondToRTS, filter=RTS_FILTER)

def runDataReceiver(capture_limit: int = 1000):
    sniff(lfilter=lambda pkt: likelyOSC, prn=respondToDataRTS, filter=RTS_FILTER)

def likelyOSC(pkt: Packet) -> bool:
    dot11_pkt = pkt[Dot11]

    return toMe(dot11_pkt) and hasOSCHeader(dot11_pkt)

def respondToDataRTS(pkt: Packet):

    if not likelyOSC(pkt):
        return

    dot11_pkt = pkt[Dot11] # sniff filter is Dot11, so this is a safe operation

    pkt_header, pkt_id, payload = OSC_ExtractParts(dot11_pkt)

    cts_response = Dot11()

    tmp = combineOSCParts(pkt_header, pkt_id, payload)
    if tmp in seen_osc_messages:
        return

    seen_osc_messages.append(tmp)
    
    print(f'Got payload {payload}')
    cts_response = generateOSC_CTSReply(dot11_pkt, payload)

    time.sleep(1) # Sleep to give sender enough time to start receiving. Unknown if necessary
    sendDot11(cts_response)
    print('Mirrored response back')


# Waits for OSC RTS and sends CTS response
def respondToRTS(pkt: Packet):
    global challenge_seq
    global normal_state
    global alert_state
    global setup_state
    global setup_id
    global current_status_fine

    dot11_pkt = pkt[Dot11] # sniff filter is Dot11, so this is a safe operation

    pkt_header, pkt_id, payload = OSC_ExtractParts(dot11_pkt)

    cts_response = Dot11()

    tmp = combineOSCParts(pkt_header, pkt_id, payload)
    if tmp in seen_osc_messages:
        return

    seen_osc_messages.append(tmp)


    if payload == OSC_REQ_SEQ or pkt_id == setup_id:
        # Clear existing setup on new connection
        if payload == OSC_REQ_SEQ:
            print('Setup seq 1/2 received')
            setup_state = 0
            setup_id = pkt_id
        else:
            print('Setup seq 2/2 received')

        canarySetupOSC(dot11_pkt)
    elif payload == challenge_seq and setup_state == 2:
        print('Challenge seq received')
        cts_response = generateOSC_CTSReply(dot11_pkt, normal_state if current_status_fine else alert_state)

        print(f'OSC RTS received: {dot11_pkt.addr2} -> reply: {cts_response.addr1}')

        time.sleep(1) # Sleep to give sender enough time to start receiving. Unknown if necessary
        sendDot11(cts_response)

        current_status_fine = False



def generateOSC_CTSReply(osc_rts: Dot11, payload: int) -> Packet:
    pkt_id = OSC_ExtractId(osc_rts)

    cts_ra = combineOSCParts(generateHeader(pkt_id, payload), pkt_id, payload)
    cts_ra_mac = intToMac(cts_ra)

    pkt = Dot11(type=CONTROL, subtype=CTS, addr1=cts_ra_mac)/Raw(load='\x00\x00')
    return pkt

# Watcher sends req, canary sends normal state
# Watcher sends challenge seq, canary sends alert state
def canarySetupOSC(dot11_pkt: Dot11):
    global normal_state
    global alert_state
    global challenge_seq
    global setup_state

    payload = ERROR

    if setup_state == 0:
        normal_state = DEFAULT_STATE_NORMAL
        payload = normal_state
        
        setup_state = 1
    elif setup_state == 1:
        challenge_seq = OSC_ExtractPayload(dot11_pkt)
        alert_state = DEFAULT_STATE_ALERT
        payload = alert_state
        setup_state = 2
        

    response = generateOSC_CTSReply(osc_rts=dot11_pkt, payload=payload)
    time.sleep(1)

    sendDot11(response)
