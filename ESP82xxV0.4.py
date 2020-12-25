#This is an Python implementation of a WiFi NAT router Manager on the esp8266 and esp8285 microcontrollers and focused on network security.
#This implementation was focused in the binary firmware ESP WiFi Repeater by Martin-Ger

#0- Don't forget that you must have python3 installed in your Laptop.
#1- Before run this implementation, you must to install in your microcontroller device the binary firmware to ESP8266 or ESP8285, it can be found at: https://github.com/martin-ger/esp_wifi_repeater
#2- Then you must to connect to the 'My AP' WiFi Access Point
#3- Then you must to start this implementation in your terminal (CMD in Windows) such as: 'python3 ESP82xxV0.4.py'
#4- Then the device will start with its new configuration that previously setted for the user.
#5- Finally, you must to manually restart your device pushing the reset bottom.

#LIBRARIES
import sys
import telnetlib
import time
import random
from datetime import datetime

#STATION SETTINGS
ALLSSIDS = (
    "SSID_OF_YOUR_WiFi_0",
    "SSID_OF_YOUR_WiFi_1",
    "SSID_OF_YOUR_WiFi_2"
    )
ALLBSSIDS = (
#    //Examples
    "D4:AB:82:AB:F8:98",
    "B0:BE:76:72:CA:9B",
    "D4:AB:82:91:B5:11"
    )
ALLPASSWORDS = (
    "YOUR_WiFi_PASSWORD_0",
    "YOUR_WiFi_PASSWORD_1",
    "YOUR_WiFi_PASSWORD_2"
    )
ALLHOSTNAMES = (
#    //To add special char, you must to use before the '\' char.
#    //Examples
    "TP-LINK\ TECHNOLOGIES\ CO\.\,LTD\.",
    "Shenzhen\ Gwelltimes\ Technology",
    "ARRIS\ Group\,\ Inc\.",
    "HUAWEI\ TECHNOLOGIES\ CO\.\,\ LTD.",
    "Hon\ Hai\ Precision\ Ind\. Co\.\,Ltd\.",
    "Xiaomi\ Communications\ Co\ Ltd",
    "iComm\ HK\ LIMITED",
    "Samsung\ Electronis\ CO\.\,LTD",
    "Liteon\ Technology\ Corporation"
)
ALLMACS = (
    //Examples
    "14:9F:3C:B9:23:A1",
    "00:87:01:97:C2:B3",
    "98:9C:57:2C:05:D3",
    "AC:07:5F:E8:72:C6",
    "C4:8E:8F:9A:7C:95",
    "EC:D0:9F:3A:98:A4",
    "68:E7:C2:95:5B:B5",
    "A4:3E:A0:17:04:70",
    "F4:C2:48:FB:AA:CB",
    "58:C5:CB:F2:D2:B7",
    "70:F1:A1:B3:A5:12",
    "48:C7:96:AB:E0:14"
    )
auto_connect = "1" #"0" Disabled; "1" Activated
client_watchdog = "60" #Uses "none" to disable

#ACCESS POINT SETTINGS
ap_ssid = "YOUR_ESP82xx_WIFI_SSID"
ap_password = "YOUR_ESP82xx_WIFI_PASSWORD"
ssid_hidden = "0" #"0" Visible network; "1" Hidden network
phy_mode = "3" #801.11 Standard Mode; 1=b, 2=g, 3=n(default)
network = "192.168.100.0"
dns = "8.8.8.8"#"8.8.8.8" #Uses "dhcp" to configures use of the dynamic DNS address from DHCP
ap_mac = "B0:BE:76:00:A1:B5"
max_clients = "5" #max_clients must be less than '8'
ap_watchdog = "180" #Uses "none" to disable

#VIRTUAL ACCESS SETTINGS
key = "YOUR_PASSWORD_TELNET_DEVICE" #Telnet key
config_access = "3" #"0" No access; "1" Only internal; "2" Only external; "3" Both
config_port = "6969" #Telnet Port
web_port = "0" #"0" Disables Web Login Interface

#TCP/IP SETTINGS
max_nat = "512" #Warning: max_nat = "0" produce several damages in your device. Default: "512"
max_portmap = "32" #Default: "32"
tcp_timeout = "1800" #Default: "1800"
udp_timeout = "2" #Default: "2"
nat = "1" #"0" Disabled; "1" Activated

#HARDWARE SETTINGS
GPIO = "2" #GPIO 2 | D4, Connect D4 to GND and reset factory device
speed = "160" #"80" or "160" Speed Clock Microcontroller
status_led = "2" #"2" LED Activated; "255" LED Disabled

#CONSTANTS FIRMWARE WiFi ESP Repeater Martin-Ger
#Don't change this constants. More about at: https://github.com/martin-ger/esp_wifi_repeater
HOST_DEFAULT = "192.168.4.1"
PORT_DEFAULT = "7777"
HOST = network[:-1] + "1"
PORT = config_port
netHOST = "8.8.8.8"
netPORT = "80"
LENGHT_HOSTNAME = 32

#SOFTWARE HYPERPARAMETERS
encode = 'ascii'
FORMAT_TIME = "%H:%M:%S "
tao = 0.10 #Delay between telnet command execution
taomessage = 1.0 #Delay between message execution
nonrepeat = 0.33 #Percentage of the data that could be use in the random selection.

#ERRORS
ERR_MAXIMUM_NAPT = "\nThe max_nat value must be than 0 or it generate a bug in the device."
ERR_DIMENSIONALITY = "\nThe ALLSSIDS, ALLBSSIDS and ALLPASSWORDS must be have the same dimensionality vector"
ERR_OVERFILL_LENGHT = "\nThe HOSTNAME must be less than 32 characters, otherwise he will be generate a bug in the device access credentials"

#STRINGS
STR_DISCONNECTED_DEVICE = "ESP8266 or ESP8285 isn't connected"
STR_DISCONNECTED_WIFI = "WiFi isn't connected"
STR_TIMEOVER = "Time Out"
STR_INVALID_COMMAND = "Invalid command"
STR_COMMAND = "Command: "
STR_COMMAND_INDEX = "\nCOMMAND INDEX:"
STR_QUIT = "quit"
STR_EXECUTED = 'Executed'
STR_TERM = "Term (min): "
STR_STEPS = "steps: "
STR_DEVICE = "sta_hostname: "
STR_MAC = "MAC: "
STR_SSID = "SSID: "
STR_RANDOM = "Random"
STR_RESETED_FACTORY_DEVICE = "Starting factory restated device"
STR_EMPTY = ""

#STRINGS SETTINGS
STR_START_SETTINGS = "Start Settings (y/n): "
STR_FINISHED_SETTINGS = "\nSETTINGS FINISHED!"
STR_SAVED_SETTINGS = "Settings saved"
STR_RESTATED_DEVICE = "\nPlease, reset and connect to your WiFi manually and don't forget put the ap_mac to get better security in your access network ESP8266 credentials"
STR_SUGGEST_CONNECT_WIFI = "\nPlease, connect to 'My AP' Access Point WiFi manually"
STR_AP_MAC = "\tap_mac: "
STR_CONNECTED_DEVICE = "Connected Device"
STR_LOCKED_DEVICE = "Locked Device"
STR_INVALID_COMMAND = "Command invalid"
STR_ASK_CONFIRMED_RESET = "\nDo you want to restated your ESP8266 device now?"
STR_SETTINGS_PARAMETERS = "\nStarting configuration to device"

if int(max_nat) <= 0 :
    print(ERR_MAXIMUM_NAPT)
    exit()

size = len(ALLSSIDS)
if not(size == len(ALLBSSIDS) and size == len(ALLPASSWORDS)):
    print(ERR_DIMENSIONALITY)
    exit()

for HOSTNAME in ALLHOSTNAMES:
    if len(HOSTNAME) - HOSTNAME.count("\\") > LENGHT_HOSTNAME:
        print(HOSTNAME)
        print(ERR_OVERFILL_LENGHT)
        exit()

ID = random.randint(0, size - 1)
ssid = ALLSSIDS[ID]
bssid = ALLBSSIDS[ID]
password = ALLPASSWORDS[ID]
sta_mac = random.choice(ALLMACS)
sta_hostname = random.choice(ALLHOSTNAMES)

SSIDS = list(ALLSSIDS)
HOSTNAMES = list(ALLHOSTNAMES)
MACS = list(ALLMACS)

def current_time(format_time = FORMAT_TIME):
    current_time = datetime.now().strftime(FORMAT_TIME)
    return current_time

class CurrentTime:
    def __init__(self, TIME_FORMAT = FORMAT_TIME):
        self.time_format = TIME_FORMAT
        self.now =  datetime.now().strftime(self.time_format)

def out(message, timer = True, taomessage = 0):
    current_time = CurrentTime()
    if timer == True:
        print(current_time.now + message)
    else:
        print(message)
    time.sleep(taomessage)
        

def refresh_device():
    global ALLHOSTNAMES
    global HOSTNAMES
    global sta_hostname
    if len(HOSTNAMES) < int(len(ALLHOSTNAMES)*(1-nonrepeat)):
        HOSTNAMES = list(ALLHOSTNAMES)
    HOSTNAMES.remove(sta_hostname)
    sta_hostname = random.choice(HOSTNAMES)

def refresh_mac():
    global ALLMACS
    global MACS
    global sta_mac    
    if len(MACS) < int(len(ALLMACS)*(1 - nonrepeat)):
        MACS = list(ALLMACS)    
    MACS.remove(sta_mac)
    sta_mac = random.choice(MACS)

def refresh_ssid():
    global ALLSSIDS
    global SSIDS
    global ssid    
    global ALLPASSWORDS
    global PASSWORDS
    global password
    if len(SSIDS) < int(len(ALLSSIDS)*(1 - nonrepeat)):
        SSIDS = list(ALLSSIDS)
    SSIDS.remove(ssid)   
    ssid = random.choice(SSIDS)
    PASSWORDS = list(ALLPASSWORDS)
    ID = SSIDS.index(ssid)
    password = PASSWORDS[ID]

def status_(HOST = HOST, PORT = PORT, tao = tao):
    status = False
    try:
        telnetObj = telnetlib.Telnet(HOST,PORT, tao)
        status = True
        telnetObj.close()
    except:
        status = False
    return status

def connect(tao = tao, HOST = HOST, PORT = PORT):
    error = True
    while error == True:
        try:
            telnetObj = telnetlib.Telnet(HOST,PORT)
            error = False
        except:
            time.sleep(tao)
    return telnetObj

def telnet(command, telnetObj, tao = tao, encode = encode, END = "\n"):
    message = (command + END).encode(encode)
    telnetObj.write(message)
    time.sleep(tao)

def reset_factory(tao = tao, key = key, HOST = HOST, PORT = PORT, HOST_DEFAULT = HOST_DEFAULT, PORT_DEFAULT = PORT_DEFAULT):
    status = status_(HOST, PORT)
    status_default = status_(HOST_DEFAULT, PORT_DEFAULT)
    while not(status == True or status_default == True):
        print(current_time() + STR_DISCONNECTED_DEVICE)
        time.sleep(taomessage)
        status = status_(HOST, PORT)
        status_default = status_(HOST_DEFAULT, PORT_DEFAULT)
    executed = False
    while not(executed):
        if status == True:
            telnetObj = connect(tao, HOST,PORT)
            telnet("unlock " + key, telnetObj)
            telnet("reset factory", telnetObj)
            print(current_time(), STR_RESETED_FACTORY_DEVICE)
            print(current_time(), STR_SUGGEST_CONNECT_WIFI)
        if status_default == True:
            telnetObj = connect(tao, HOST_DEFAULT, PORT_DEFAULT)
        status_default = status_(HOST_DEFAULT, PORT_DEFAULT)
        while status_default == False:
            print(current_time() + STR_DISCONNECTED_DEVICE)
            time.sleep(taomessage)
            status_default = status_(HOST_DEFAULT, PORT_DEFAULT)
        executed = True
    default_executed = False
    while not(default_executed):
        telnetObj= connect(tao, HOST_DEFAULT, PORT_DEFAULT)
        print(current_time(), STR_SETTINGS_PARAMETERS)
        telnet("set hw_reset " + GPIO,telnetObj)
        out("GPIO reset: " + GPIO)
        telnet("set ap_ssid " + ap_ssid, telnetObj)
        out("ap_ssid: " + ap_ssid)  
        telnet("set ap_password " + ap_password, telnetObj)
        out("ap_password: " + ap_password)
        telnet("set ssid_hidden " + ssid_hidden, telnetObj)
        out("ssid_hidden: " + ssid_hidden)
        telnet("set phy_mode " + phy_mode, telnetObj)
        out("phy_mode: " + phy_mode)
        telnet("set network " + network, telnetObj)
        out("network: " + network)
        telnet("set config_port " + config_port, telnetObj)
        out("config_port: " + config_port)
        telnet("set speed " + speed, telnetObj)
        out("speed: " + speed)
        telnet("set config_access " + config_access, telnetObj)
        out("config_access: " + config_access)
        telnet("set web_port " + web_port, telnetObj)
        out("web_port: " + web_port)
        telnet("set dns " + dns, telnetObj)
        out("dns: " + dns)
        telnet("set max_clients " + max_clients, telnetObj)
        out("max_clients: " + max_clients)
        telnet("set sta_mac " + sta_mac, telnetObj)
        out("sta_mac: " + sta_mac)
        telnet("set sta_hostname " + sta_hostname, telnetObj)
        out("sta_hostname: " + sta_hostname)
        telnet("set ap_mac " + ap_mac, telnetObj)
        out("ap_mac: " + ap_mac)
        telnet("set ap_watchdog " + ap_watchdog, telnetObj)
        out("ap_watchdog: " + ap_watchdog)
        telnet("set client_watchdog " + client_watchdog, telnetObj)
        out("client_watchdog: " + client_watchdog)
        telnet("set ssid " + ssid, telnetObj)
        out("ssid: " + ssid)
        telnet("set password " + password, telnetObj)
        out("password: " + password)
        telnet("set bssid " + bssid, telnetObj)
        out("bssid: " + bssid)
        telnet("set max_nat " + max_nat, telnetObj)
        out("max_nat: " + max_nat)
        telnet("set max_portmap " + max_portmap, telnetObj)
        out("max_portmap: " + max_portmap)
        telnet("set tcp_timeout " + tcp_timeout, telnetObj)
        out("tcp_timeout: " + tcp_timeout)
        telnet("set udp_timeout " + udp_timeout, telnetObj)
        out("udp_timeout: " + udp_timeout)
        telnet("set nat " + nat, telnetObj)
        out("nat: " + nat)
        telnet("set max_nat " + max_nat, telnetObj)
        out("max_nat: " + max_nat)
        telnet("set auto_connect " + auto_connect, telnetObj)
        out("auto_connect: " + auto_connect)
        if auto_connect == 1:
            telnet("connect", telnetObj)
            print(current_time(), STR_CONNECTED_DEVICE)
        telnet("set status_led " + status_led, telnetObj)
        out("status_led: " + status_led)
        telnet("save", telnetObj)
        print(current_time(), STR_SAVED_SETTINGS)
        telnet("lock " + key, telnetObj)
        print(current_time(), STR_LOCKED_DEVICE)
        telnet("quit", telnetObj)
        telnetObj.close()
        print(current_time(), STR_FINISHED_SETTINGS)
        print(current_time(), STR_RESTATED_DEVICE)
        print(STR_AP_MAC + ap_mac)
        time.sleep(taomessage)
        default_executed = True
        #exit()
    
def reset(tao = tao, key = key, HOST = HOST, PORT = PORT):
    telnetObj=telnetlib.Telnet(HOST,PORT)
    message = ("unlock " + key + "\n").encode('ascii')
    telnetObj.write(message)
    time.sleep(tao)
    message = ("reset" + "\n").encode('ascii')
    telnetObj.write(message)
    time.sleep(tao)
    telnetObj = connect(tao = tao, HOST = HOST, PORT = PORT)
    message = ("lock"+"\n").encode('ascii')
    telnetObj.write(message)
    telnetObj.close()

def changemac(randoms, tao = tao, key = key, HOST = HOST, PORT = PORT):
    global sta_mac
    global sta_hostname
    if randoms == False:
        refresh_mac()
    telnetObj=telnetlib.Telnet(HOST,PORT)
    message = ("unlock " + key + "\n").encode('ascii')
    telnetObj.write(message)
    time.sleep(tao)
    if randoms == False:
        message = ("set sta_mac " + sta_mac + "\n").encode('ascii')
    if randoms == True:
        message = ("set sta_mac random" + "\n").encode('ascii')
    telnetObj.write(message)
    time.sleep(tao)
    refresh_device()
    message = ("set sta_hostname " + sta_hostname +"\n").encode('ascii')
    telnetObj.write(message)
    time.sleep(tao)
    message = ("save"+"\n").encode('ascii')
    telnetObj.write(message)
    time.sleep(tao)
    message = ("lock"+"\n").encode('ascii')
    telnetObj.write(message)
    telnetObj.close()
    reset(tao, key, HOST, PORT)
    if randoms == False:
        print(current_time(), STR_MAC,sta_mac)
    else:
        print(current_time(), STR_MAC, STR_RANDOM)
    print(current_time(), STR_DEVICE, sta_hostname)

def changessid(tao = tao, key = key, HOST = HOST, PORT = PORT):
    global ssid
    global password
    refresh_ssid()
    telnetObj = telnetlib.Telnet(HOST,PORT)
    telnet("unlock " + key, telnetObj)
    telnet("set ssid " + ssid, telnetObj)
    telnet("set password " + password, telnetObj)
    telnet("save", telnetObj)
    telnet("lock " + key, telnetObj)
    telnetObj.close()
    reset(tao, key, HOST, PORT)
    print(current_time(), STR_SSID,ssid)

def led(on, tao = tao, key = key, HOST = HOST, PORT = PORT):
    telnetObj=telnetlib.Telnet(HOST,PORT)
    message = ("unlock " + key + "\n").encode('ascii')
    telnetObj.write(message)
    time.sleep(tao)
    if on == True:
        message = ("set status_led 2" + "\n").encode('ascii')
    if on == False:
        message = ("set status_led 255" + "\n").encode('ascii')
    telnetObj.write(message)
    time.sleep(tao)
    message = ("save" + "\n").encode('ascii')
    telnetObj.write(message)
    time.sleep(tao)
    message = ("lock"+"\n").encode('ascii')
    telnetObj.write(message)
    telnetObj.close()

command_index = [
                 'led on',
                 'led off',
                 'reset',
                 'reset auto',
                 'reset factory',
                 'changemac',
                 'changemac auto',
                 'changemac random',
                 'changemac random auto',
                 'changessid',
                 'changessid auto'
                 ]

def changemac_auto(randoms, tao = tao, key = key, HOST = HOST, PORT = PORT, netHOST = netHOST, netPORT = netPORT):
    taonet = (float(input(STR_TERM)) * 60)
    clock = time.time()
    while True:
        try:
            localstatus = status_(HOST,PORT)
            if localstatus == False:
                print(current_time() + STR_DISCONNECTED_DEVICE)
                time.sleep(taomessage)
            else:
                netstatus = status_(netHOST, netPORT)
                if netstatus == False:
                    print(current_time(), STR_DISCONNECTED_WIFI)
                    time.sleep(taomessage)
                else:
                    if (time.time() - clock > taonet):
                        print(current_time(), STR_TIMEOVER)
                        time.sleep(taomessage)
                if netstatus == False or (time.time() - clock > taonet):
                    changemac(randoms = randoms)
                    clock = time.time()
                    netstatus = status_(netHOST, netPORT)
                time.sleep(tao)
        except:
            time.sleep(tao)

def changessid_auto(tao = tao, key = key, HOST = HOST, PORT = PORT, netHOST = netHOST, netPORT = netPORT):
    taonet = (float(input(STR_TERM)) * 60)
    clock = time.time()
    while True:
        try:
            localstatus = status_(HOST,PORT)
            if localstatus == False:
                print(current_time() + STR_DISCONNECTED_DEVICE)
                time.sleep(taomessage)
            else:
                netstatus = status_(netHOST, netPORT)
                if netstatus == False:
                    print(current_time(), STR_DISCONNECTED_WIFI)
                    time.sleep(taomessage)
                else:
                    if (time.time() - clock > taonet):
                        print(current_time(), STR_TIMEOVER)
                        time.sleep(taomessage)
                if netstatus == False or (time.time() - clock > taonet):
                    changessid()
                    clock = time.time()
                    netstatus = status_(netHOST, netPORT)
                time.sleep(tao)
        except:
            time.sleep(tao)

def reset_auto(tao = tao, key = key, HOST = HOST, PORT = PORT):
    steps = int(input(STR_STEPS))
    telnetObj=telnetlib.Telnet(HOST,PORT)
    message = ("unlock " + key + "\n").encode('ascii')
    telnetObj.write(message)
    time.sleep(tao)
    for i in range(steps):
        message = ("reset" + "\n").encode('ascii')
        telnetObj.write(message)
        time.sleep(tao)
        telnetObj = connect(tao = tao, HOST = HOST, PORT = PORT)
    message = ("lock"+"\n").encode('ascii')
    telnetObj.write(message)
    telnetObj.close()

def principal(command, taomessage = taomessage, command_index = command_index):
    if command == command_index[0]:
        led(on = True)
    if command == command_index[1]:
        led(on = False)
    if command == command_index[2]:
        reset()
    if command == command_index[3]:
        reset_auto()
    if command == command_index[4]:
        reset_factory()
    if command == command_index[5]:
        changemac(randoms = False)
    if command == command_index[6]:
        changemac_auto(randoms = False)
    if command == command_index[7]:
        changemac(randoms = True)
    if command == command_index[8]:
        changemac_auto(randoms = True)
    if command == command_index[9]:
        changessid()
    if command == command_index[10]:
        changessid_auto()

    print(current_time(), STR_EXECUTED)
    time.sleep(taomessage)

status_default = status_(HOST_DEFAULT, PORT_DEFAULT)
status = status_()
#If the network has the same default parameters then ask to user if he wants to restate the device.
while not (status == True or status_default == True ):
    print(current_time() + STR_DISCONNECTED_DEVICE)
    time.sleep(taomessage)
    status_default = status_(HOST_DEFAULT, PORT_DEFAULT)
    status = status_()
if status_default == True:
    if HOST == HOST_DEFAULT and PORT == PORT_DEFAULT:
        exit = False
        while not exit:
            confirm_input = input(STR_ASK_CONFIRMED_RESET)
            if confirm_input == 'y':
                reset_factory()
                exit = True
            if confirm_input == 'n':
                exit = True
            if confirm_input != 'y' and confirm_input != 'n':
                print(current_time() + STR_INVALID_COMMAND)
    else:
        reset_factory()

print(current_time(), STR_COMMAND_INDEX)
for index in command_index:
    print(index)
exit = False
while not exit:
    command_input = input(STR_COMMAND)
    if command_input == STR_QUIT:
        exit = True
    if command_input in command_index:
        principal(command_input)
    if command_input not in command_index and command_input != STR_QUIT:
        print(current_time() + STR_INVALID_COMMAND)
