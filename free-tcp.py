#┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#┃ 𝘾𝙤𝙙𝙚 𝘿𝙚𝙫𝙚𝙡𝙤𝙥𝙚𝙙 𝘽𝙮 𝘾𝙊𝘿𝙀-𝙓 𝙅𝙊𝘽𝘼𝙔𝘼𝙍   
#┃ 𝘿𝙊𝙉𝙏 𝘾𝙃𝘼𝙉𝙂𝙀 𝙈𝙔 𝘾𝙍𝙀𝘿𝙄𝙏                
#┃ 𝘿𝙀𝙑𝙇𝙊𝙋𝙀𝙍 𝙏𝙂 ➯ @JOBAYAR_AHMED     
#┃ 𝘽𝙐𝙔 𝙋𝘼𝙄𝙏 𝙎𝘾𝙍𝙀𝙋𝙏 ➯ @JOBAYAR_AHMED
#┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
import threading
import jwt
import random
from threading import Thread
import json
import requests 
import google.protobuf
from protobuf_decoder.protobuf_decoder import Parser
import datetime
from datetime import datetime
from google.protobuf.json_format import MessageToJson
import my_message_pb2
import data_pb2
import base64
import logging
import re
import socket
from google.protobuf.timestamp_pb2 import Timestamp
import jwt_generator_pb2
import os
import binascii
import sys
import psutil
import MajorLoginRes_pb2
from time import sleep
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import urllib3
from important_zitado import*
from byte import*

# --- Global Variables for State Management ---
statusinfo = False
tempdata1 = None
tempdata = None
data22 = None

# --- Configuration ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
client_secret = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
chat_ip = "98.98.162.80"
chat_port = 39699

# --- Helper Functions ---

def encrypt_packet(plain_text, key, iv):
    """Encrypts data using AES CBC mode for game packets."""
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def get_player_status(packet):
    """Parses a packet to determine a player's online status."""
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)

    try:
        status = parsed_data["5"]["data"]["1"]["data"]["3"]["data"]
        if status == 1:
            return "SOLO"
        if status == 2:
            group_count = parsed_data["5"]["data"]["1"]["data"]["9"]["data"]
            count_max = parsed_data["5"]["data"]["1"]["data"]["10"]["data"] + 1
            return f"IN SQUAD ({group_count}/{count_max})"
        if status in [3, 5]:
            return "IN GAME"
        if status == 4:
            return "IN ROOM"
        if status in [6, 7]:
            return "IN SOCIAL ISLAND"
        return "UNKNOWN STATUS"
    except (KeyError, TypeError):
        return "OFFLINE"

def get_idroom_by_idplayer(packet):
    """Extracts the room ID from a player status packet."""
    try:
        json_result = get_available_room(packet)
        parsed_data = json.loads(json_result)
        idroom = parsed_data["5"]["data"]["1"]["data"]['15']["data"]
        return idroom
    except (KeyError, TypeError):
        return None

def get_leader(packet):
    """Extracts the squad leader's ID from a player status packet."""
    try:
        json_result = get_available_room(packet)
        parsed_data = json.loads(json_result)
        leader = parsed_data["5"]["data"]["1"]["data"]['8']["data"]
        return leader
    except (KeyError, TypeError):
        return None
        
def generate_random_color():
    """Returns a random color code for in-game chat."""
    color_list = [
        "[00FF00][b][c]", "[FFDD00][b][c]", "[3813F3][b][c]", "[FF0000][b][c]",
        "[0000FF][b][c]", "[FFA500][b][c]", "[DF07F8][b][c]", "[11EAFD][b][c]"
    ]
    return random.choice(color_list)

def fix_num(num):
    """Formats numbers with a [c] separator for better in-game display."""
    fixed = ""
    count = 0
    for char in str(num):
        if char.isdigit():
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed

def check_banned_status(player_id):
    """Checks a player's ban status using a web API."""
    url = f"http://amin-team-api.vercel.app/check_banned?player_id={player_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"API Error: Status code {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def get_player_info_from_api(uid):
    """Fetches detailed player information from a web API."""
    try:
        url = f"https://info-murex.vercel.app/{uid}"
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            # Standardize response structure
            if "basicinfo" in data and data["basicinfo"]:
                data["basic_info"] = data["basicinfo"][0]
            else:
                return {"status": "wrong_id"}
            
            data["clan_info"] = data.get("claninfo", [None])[0]
            data["clan_admin"] = data.get("clanadmin", [None])[0]
            
            return {"status": "ok", "info": data}
        else:
            return {"status": "wrong_id"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def send_likes(uid):
    """
    Handles sending likes to a player.
    NOTE: The API endpoint is a placeholder. You must replace it with a valid URL.
    """
    api_url = "HERE IS THE API LIKES" # <-- IMPORTANT: Replace this with your actual API URL

    if api_url == "HERE IS THE API LIKES":
        return {
            "status": "failed",
            "message": (
                f"[C][B][FF0000]________________________\n"
                f" ❌ Likes service is not configured.\n"
                f" The bot owner needs to set the API URL in the script.\n"
                f"________________________"
            )
        }
    
    try:
        likes_api_response = requests.get(f"{api_url}/{uid}") # Example endpoint
        if likes_api_response.status_code == 200:
            api_data = likes_api_response.json()
            if api_data.get("LikesGivenByAPI", 0) == 0:
                return { "status": "failed", "message": "[C][B][FF0000]Daily limit for sending likes reached!" }
            else:
                return {
                    "status": "ok",
                    "message": (
                        f"[C][B][00FF00]________________________\n"
                        f" ✅ Added {api_data['LikesGivenByAPI']} likes!\n"
                        f" To: {api_data['PlayerNickname']}\n"
                        f" Previous Likes: {api_data['LikesbeforeCommand']}\n"
                        f" New Total Likes: {api_data['LikesafterCommand']}\n"
                        f"________________________"
                    )
                }
        else:
            return { "status": "failed", "message": "[C][B][FF0000]Failed to send likes. Please check the Player ID."}
    except requests.exceptions.RequestException:
        return { "status": "failed", "message": "[C][B][FF0000]Could not connect to the likes service." }

def Encrypt(number):
    """Encodes a number into a variable-length quantity hex string."""
    number = int(number)
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes).hex()

def get_random_avatar():
    """Selects a random avatar ID from a predefined list."""
    avatar_list = [
        '902000061', '902000060', '902000064', '902000065', '902000066', 
        '902000074', '902000075', '902000077', '902000078', '902000084'
    ]
    return random.choice(avatar_list)

# --- Main Bot Class ---

class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()

    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            key = MajorLogRes.ak.hex() if isinstance(MajorLogRes.ak, bytes) else MajorLogRes.ak
            iv = MajorLogRes.aiv.hex() if isinstance(MajorLogRes.aiv, bytes) else MajorLogRes.aiv
            self.key = key
            self.iv = iv
            print(f"Key and IV obtained successfully.")
            return self.key, self.iv
        except Exception as e:
            print(f"Error parsing login response: {e}")
            return None, None

    def nmnmmmmn(self, data):
        """Wrapper for the main packet encryption function."""
        try:
            key = bytes.fromhex(self.key)
            iv = bytes.fromhex(self.iv)
            data = bytes.fromhex(data)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
            return cipher_text.hex()
        except Exception as e:
            print(f"Error in encryption wrapper: {e}")
            return None

    # --- Packet Creation Methods ---
    def create_squad(self):
        fields = {1: 1, 2: {2: "\u0001", 3: 1, 4: 1, 5: "en", 9: 1, 11: 1, 13: 1, 14: {2: 5756, 6: 11, 8: "1.109.5", 9: 3, 10: 2}}}
        packet = create_protobuf_packet(fields).hex()
        header_lenth = len(encrypt_packet(packet, key, iv)) // 2
        header_lenth_final = dec_to_hex(header_lenth)
        final_packet = f"0515000000{header_lenth_final.zfill(2)}{self.nmnmmmmn(packet)}"
        return bytes.fromhex(final_packet)

    def set_squad_properties(self, num):
        fields = {1: 17, 2: {1: 11371687918, 2: 1, 3: int(num), 4: 62, 5: "\u001a", 8: 5, 13: 329}}
        packet = create_protobuf_packet(fields).hex()
        header_lenth = len(encrypt_packet(packet, key, iv)) // 2
        header_lenth_final = dec_to_hex(header_lenth)
        final_packet = f"0515000000{header_lenth_final.zfill(2)}{self.nmnmmmmn(packet)}"
        return bytes.fromhex(final_packet)

    def leave_squad(self):
        fields = {1: 7, 2: {1: 11371687918}}
        packet = create_protobuf_packet(fields).hex()
        header_lenth = len(encrypt_packet(packet, key, iv)) // 2
        header_lenth_final = dec_to_hex(header_lenth)
        final_packet = f"0515000000{header_lenth_final.zfill(2)}{self.nmnmmmmn(packet)}"
        return bytes.fromhex(final_packet)

    def invite_to_squad(self, idplayer):
        fields = {1: 2, 2: {1: int(idplayer), 2: "ME", 4: 1}}
        packet = create_protobuf_packet(fields).hex()
        header_lenth = len(encrypt_packet(packet, key, iv)) // 2
        header_lenth_final = dec_to_hex(header_lenth)
        final_packet = f"0515000000{header_lenth_final.zfill(2)}{self.nmnmmmmn(packet)}"
        return bytes.fromhex(final_packet)

    def GenResponsMsg(self, Msg, Enc_Id):
        fields = {
            1: 1, 2: {
                1: 3557944186, 2: Enc_Id, 3: 2, 4: str(Msg), 5: int(datetime.now().timestamp()),
                9: {2: int(get_random_avatar()), 3: 901041021, 4: 330, 10: 1, 11: 155},
                10: "en",
                13: {1: "https://graph.facebook.com/v9.0/104076471965380/picture?width=160&height=160", 2: 1, 3: 1}
            }, 14: ""
        }
        packet = create_protobuf_packet(fields).hex()
        header_lenth = len(encrypt_packet(packet, key, iv)) // 2
        header_lenth_final = dec_to_hex(header_lenth)
        final_packet = f"1215000000{header_lenth_final.zfill(2)}{self.nmnmmmmn(packet)}"
        return bytes.fromhex(final_packet)

    def createpacketinfo(self, idddd):
        ida = Encrypt(idddd)
        packet = f"080112090A05{ida}1005"
        header_lenth = len(encrypt_packet(packet, key, iv)) // 2
        header_lenth_final = dec_to_hex(header_lenth)
        final_packet = f"0F15000000{header_lenth_final.zfill(2)}{self.nmnmmmmn(packet)}"
        return bytes.fromhex(final_packet)

    def info_room(self, idrooom):
        fields = {1: 1, 2: {1: int(idrooom), 3: {}, 4: 1, 6: "en"}}
        packet = create_protobuf_packet(fields).hex()
        header_lenth = len(encrypt_packet(packet, key, iv)) // 2
        header_lenth_final = dec_to_hex(header_lenth)
        final_packet = f"0E15000000{header_lenth_final.zfill(2)}{self.nmnmmmmn(packet)}"
        return bytes.fromhex(final_packet)
    
    # --- Socket Handling ---

    def sockf1(self, tok, online_ip, online_port, packet, key, iv):
        """Handles the 'online' socket for gameplay events."""
        global socket_client, statusinfo, tempdata, data22, tempdata1
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_client.connect((online_ip, int(online_port)))
        print(f"Connected to Online Server: {online_ip}:{online_port}")
        socket_client.send(bytes.fromhex(tok))

        while True:
            try:
                data2 = socket_client.recv(9999)
                if data2 == b"":
                    print("Online server connection closed.")
                    restart_program()
                    break

                if "0f00" in data2.hex()[:4]:
                    packett = f'08{data2.hex().split("08", 1)[1]}'
                    kk = get_available_room(packett)
                    parsed_data = json.loads(kk)
                    
                    if parsed_data.get("2", {}).get("data") == 15:
                        tempdata = get_player_status(packett)
                        if tempdata == "OFFLINE":
                            tempdata = "Player is OFFLINE."
                        else:
                            player_id = parsed_data["5"]["data"]["1"]["data"]["1"]["data"]
                            id_formatted = fix_num(player_id)
                            if tempdata == "IN ROOM":
                                room_id = get_idroom_by_idplayer(packett)
                                tempdata = f"ID: {id_formatted}\nStatus: {tempdata}\nRoom ID: {fix_num(room_id)}"
                                data22 = packett
                            elif "IN SQUAD" in tempdata:
                                leader_id = get_leader(packett)
                                tempdata = f"ID: {id_formatted}\nStatus: {tempdata}\nLeader ID: {fix_num(leader_id)}"
                            else:
                                tempdata = f"ID: {id_formatted}\nStatus: {tempdata}"
                        statusinfo = True 

                if "0e00" in data2.hex()[:4]:
                    packett = f'08{data2.hex().split("08", 1)[1]}'
                    kk = get_available_room(packett)
                    parsed_data = json.loads(kk)
                    if parsed_data.get("2", {}).get("data") == 14:
                        room_name = parsed_data["5"]["data"]["1"]["data"]["2"]["data"]
                        max_players = parsed_data["5"]["data"]["1"]["data"]["7"]["data"]
                        current_players = parsed_data["5"]["data"]["1"]["data"]["6"]["data"]
                        tempdata1 = f"{tempdata}\nRoom Name: {room_name}\nPlayers: {current_players}/{max_players}"
            except Exception as e:
                print(f"Error in online socket loop: {e}")
                restart_program()
                break

    def connect(self, tok, packet, key, iv, whisper_ip, whisper_port, online_ip, online_port):
        """Handles the 'whisper' socket for chat commands."""
        global clients, socket_client, statusinfo, tempdata, tempdata1, data22
        
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clients.connect((whisper_ip, whisper_port))
        print(f"Connected to Whisper Server: {whisper_ip}:{whisper_port}")
        clients.send(bytes.fromhex(tok))
        
        thread = threading.Thread(target=self.sockf1, args=(tok, online_ip, online_port, "anything", key, iv))
        threads.append(thread)
        thread.start()

        while True:
            try:
                data = clients.recv(9999)
                if data == b"":
                    print("Whisper server connection closed.")
                    break
                
                if "1200" not in data.hex()[:4]:
                    continue

                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                
                message_content = data.decode('utf-8', errors='ignore')

                # --- Command Handling ---

                if "/dev" in message_content:
                    clients.send(self.GenResponsMsg(
                        f"{generate_random_color()}This bot is credited to @JOBAYAR_AHMED.", uid
                    ))

                elif "/3s" in message_content:
                    command_parts = re.split(r"/3s\s*", message_content)[1].split('(')[0].strip().split()
                    target_id = command_parts[0] if command_parts else uid
                    
                    clients.send(self.GenResponsMsg(f"[00FF00]Creating a 3-player squad and inviting {fix_num(target_id)}...", uid))
                    
                    socket_client.send(self.create_squad())
                    sleep(0.5)
                    socket_client.send(self.set_squad_properties(2)) # 2 means 3 players
                    sleep(0.5)
                    socket_client.send(self.invite_to_squad(target_id))
                    
                    sleep(5) # Auto-leave after 5 seconds
                    socket_client.send(self.leave_squad())
                    sleep(1)
                    socket_client.send(self.set_squad_properties(1)) # Return to solo

                elif "/status" in message_content:
                    command_parts = re.split(r"/status\s*", message_content)[1].split('(')[0].strip().split()
                    if not command_parts:
                        clients.send(self.GenResponsMsg("[FF0000]Please provide a Player ID. Usage: /status <id>", uid))
                        continue
                    
                    player_id = command_parts[0]
                    clients.send(self.GenResponsMsg(f"[FFFF00]Fetching status for {fix_num(player_id)}...", uid))
                    
                    socket_client.send(self.createpacketinfo(player_id))
                    
                    statusinfo1 = True
                    start_time = time.time()
                    while statusinfo1 and (time.time() - start_time < 5): # 5-second timeout
                        if statusinfo:
                            if "IN ROOM" in tempdata and data22:
                                room_id = get_idroom_by_idplayer(data22)
                                if room_id:
                                    socket_client.send(self.info_room(room_id))
                                    sleep(0.5)
                                    clients.send(self.GenResponsMsg(f"{tempdata1}", uid))
                                else:
                                    clients.send(self.GenResponsMsg(f"{tempdata}", uid))
                            else:
                                clients.send(self.GenResponsMsg(f"{tempdata}", uid))
                            
                            tempdata = tempdata1 = data22 = None
                            statusinfo = False
                            statusinfo1 = False
                    
                    if statusinfo1: # If loop timed out
                        clients.send(self.GenResponsMsg(f"[FF0000]Could not retrieve status for {fix_num(player_id)}. Player might be offline.", uid))


                elif "/info" in message_content:
                    command_parts = re.split(r"/info\s*", message_content)[1].split('(')[0].strip().split()
                    if not command_parts:
                        clients.send(self.GenResponsMsg("[FF0000]Please provide a Player ID. Usage: /info <id>", uid))
                        continue

                    player_id = command_parts[0]
                    clients.send(self.GenResponsMsg(f"[FFFF00]Fetching info for {fix_num(player_id)}...", uid))
                    
                    info_response = get_player_info_from_api(player_id)
                    
                    if info_response['status'] != "ok":
                        clients.send(self.GenResponsMsg("[FF0000]Invalid Player ID or API error. Please check the ID.", uid))
                    else:
                        info = info_response['info']
                        basic = info['basic_info']
                        clan = info.get('clan_info')
                        
                        clan_text = "[b]Player is not in a clan."
                        if clan:
                            clan_text = (
                                f"[B][00FF00]Clan Info:\n"
                                f"[B]• Name: [FFFFFF]{clan.get('clanname', 'N/A')}\n"
                                f"[B]• Members: [FFFFFF]{clan.get('livemember', 0)}\n"
                                f"[B]• Level: [FFFFFF]{clan.get('guildlevel', 0)}"
                            )
                        
                        message = (
                            f"[C][B][00FF00]«--- Player Info ---»\n"
                            f"[B]• Name: [FFFFFF]{basic.get('username', 'N/A')}\n"
                            f"[B]• Level: [FFFFFF]{basic.get('level', 'N/A')}\n"
                            f"[B]• Server: [FFFFFF]{basic.get('region', 'N/A')}\n"
                            f"[B]• Likes: [FFFFFF]{fix_num(basic.get('likes', 0))}\n"
                            f"[B]• Bio: [FFFFFF]{basic.get('bio', 'No bio.').replace('|', ' ')}\n"
                            f"________________________\n{clan_text}"
                        )
                        clients.send(self.GenResponsMsg(message, uid))

                elif "/likes" in message_content:
                    command_parts = re.split(r"/likes\s*", message_content)[1].split('(')[0].strip().split()
                    if not command_parts:
                        clients.send(self.GenResponsMsg("[FF0000]Please provide a Player ID. Usage: /likes <id>", uid))
                        continue
                        
                    player_id = command_parts[0]
                    clients.send(self.GenResponsMsg(f"{generate_random_color()}Processing likes request...", uid))
                    
                    likes_result = send_likes(player_id)
                    clients.send(self.GenResponsMsg(likes_result['message'], uid))

                elif "/check" in message_content:
                    command_parts = re.split(r"/check\s*", message_content)[1].split('(')[0].strip().split()
                    if not command_parts:
                        clients.send(self.GenResponsMsg("[FF0000]Please provide a Player ID. Usage: /check <id>", uid))
                        continue
                    
                    player_id = command_parts[0]
                    clients.send(self.GenResponsMsg(f"{generate_random_color()}Checking ban status for {fix_num(player_id)}...", uid))
                    
                    status = check_banned_status(player_id)
                    if 'error' in status:
                        response_message = f"[FF0000]Error: {status['error']}"
                    else:
                        response_message = (
                            f"{generate_random_color()}Player Name: {status.get('player_name', 'Unknown')}\n"
                            f"Player ID: {fix_num(player_id)}\n"
                            f"Status: {status.get('status', 'Unknown')}"
                        )
                    clients.send(self.GenResponsMsg(response_message, uid))

                elif "/help" in message_content:
                    user_name = parsed_data['5']['data']['9']['data']['1']['data']
                    help_message = (
                        f"[C][B][FFFFFF]Welcome, {user_name}!\n"
                        f"Here are the available commands:\n\n"
                        f"[FFA500]● /info <id>[FFFFFF] - Get player information.\n"
                        f"[FFA500]● /status <id>[FFFFFF] - Check player's current status.\n"
                        f"[FFA500]● /check <id>[FFFFFF] - Check if a player is banned.\n"
                        f"[FFA500]● /likes <id>[FFFFFF] - Send likes to a player.\n"
                        f"[FFA500]● /3s [id][FFFFFF] - Create a 3-player squad and invite.\n"
                        f"[FFA500]● /dev[FFFFFF] - Show developer information."
                    )
                    clients.send(self.GenResponsMsg(help_message, uid))

            except Exception as e:
                print(f"Error in whisper socket loop: {e}")
                break

    # --- Login and Initialization Logic (largely unchanged) ---
    def parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv, BASE64_TOKEN
        
    def GET_PAYLOAD_BY_DATA(self,JWT_TOKEN , NEW_ACCESS_TOKEN,date):
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now =str(now)[:len(str(now))-7]
        formatted_time = date
        payload = bytes.fromhex("1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033")
        payload = payload.replace(b"2025-07-30 11:02:51", str(now).encode())
        payload = payload.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"996a629dbcdb3964be6b6978f5d814db", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfebdf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = encrypt_api(payload.hex())
        whisper_ip, whisper_port, online_ip, online_port = self.GET_LOGIN_DATA(JWT_TOKEN , bytes.fromhex(PAYLOAD))
        return whisper_ip, whisper_port, online_ip, online_port
    
    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = "https://clientbp.common.ggbluefox.com/GetLoginData"
        headers = {'Authorization': f'Bearer {JWT_TOKEN}', 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Dalvik/2.1.0'}
        try:
            response = requests.post(url, headers=headers, data=PAYLOAD, verify=False)
            response.raise_for_status()
            json_result = get_available_room(response.content.hex())
            parsed_data = json.loads(json_result)
            whisper_address = parsed_data['32']['data']
            online_address = parsed_data['14']['data']
            online_ip, online_port = online_address.rsplit(':', 1)
            whisper_ip, whisper_port = whisper_address.rsplit(':', 1)
            return whisper_ip, int(whisper_port), online_ip, int(online_port)
        except requests.RequestException as e:
            print(f"Failed to get login data: {e}")
            return None, None, None, None

    def guest_token(self,uid , password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"User-Agent": "GarenaMSDK/4.0.19P4", "Content-Type": "application/x-www-form-urlencoded"}
        data = {"uid": f"{uid}", "password": f"{password}", "response_type": "token", "client_type": "2", "client_secret": client_secret, "client_id": "100067"}
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        return self.TOKEN_MAKER(NEW_ACCESS_TOKEN, uid)
        
    def TOKEN_MAKER(self, NEW_ACCESS_TOKEN, id):
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Dalvik/2.1.0'}
        data = bytes.fromhex('1a13323032352d30372d33302031313a30323a3531220966726565206669726528013a07312e3131342e32422c416e64726f6964204f5320372e312e32202f204150492d323320284e32473438482f373030323530323234294a0848616e6468656c645207416e64726f69645a045749464960c00c68840772033332307a1f41524d7637205646507633204e454f4e20564d48207c2032343635207c203480019a1b8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e319a012b476f6f676c657c31663361643662372d636562342d343934622d383730622d623164616364373230393131a2010c3139372e312e31322e313335aa0102656eb201203939366136323964626364623339363462653662363937386635643831346462ba010134c2010848616e6468656c64ca011073616d73756e6720534d2d473935354eea014066663930633037656239383135616633306134336234613966363031393531366530653463373033623434303932353136643064656661346365663531663261f00101ca0207416e64726f6964d2020457494649ca03203734323862323533646566633136343031386336303461316562626665626466e003daa907e803899b07f003bf0ff803ae088004999b078804daa9079004999b079804daa907c80403d204262f646174612f6170702f636f6d2e6474732e667265656669726574682d312f6c69622f61726de00401ea044832303837663631633139663537663261663465376665666630623234643964397c2f646174612f6170702f636f6d2e6474732e667265656669726574682d312f626173652e61706bf00403f804018a050233329a050a32303139313138363933a80503b205094f70656e474c455332b805ff7fc00504e005dac901ea0507616e64726f6964f2055c4b71734854394748625876574c6668437950416c52526873626d43676542557562555551317375746d525536634e30524f3751453141486e496474385963784d614c575437636d4851322b7374745279377830663935542b6456593d8806019006019a060134a2060134b2061e40001147550d0c074f530b4d5c584d57416657545a065f2a091d6a0d5033')
        # This payload replacement is complex and specific to the game version.
        # It's replacing hardcoded old tokens with the new ones for the current session.
        data = data.replace(b"996a629dbcdb3964be6b6978f5d814db", id.encode())
        data = data.replace(b"ff90c07eb9815af30a43b4a9f6019516e0e4c703b44092516d0defa4cef51f2a" , NEW_ACCESS_TOKEN.encode())
        Final_Payload = bytes.fromhex(encrypt_api(data.hex()))
        
        RESPONSE = requests.post("https://loginbp.ggblueshark.com/MajorLogin", headers=headers, data=Final_Payload, verify=False)
        
        if RESPONSE.status_code == 200 and len(RESPONSE.text) > 10:
            combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
            self.key, self.iv = key.hex(), iv.hex()
            whisper_ip, whisper_port, online_ip, online_port = self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN, NEW_ACCESS_TOKEN, 1)
            return BASE64_TOKEN, key, iv, combined_timestamp, whisper_ip, whisper_port, online_ip, online_port
        else:
            print(f"Token Maker failed. Status: {RESPONSE.status_code}")
            return False, None, None, None, None, None, None, None

    def get_tok(self):
        global g_token, key, iv
        token_data = self.guest_token(self.id, self.password)
        if not token_data[0]:
            print(f"Failed to get token for ID: {self.id}")
            return

        token, key, iv, Timestamp, whisper_ip, whisper_port, online_ip, online_port = token_data
        g_token = token
        
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            encoded_acc = hex(account_id)[2:]
            hex_value = dec_to_hex(Timestamp)
            BASE64_TOKEN_ = token.encode().hex()
            
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            zeros = '0' * (12 - len(encoded_acc))
            
            head = f'0115{zeros}{encoded_acc}{hex_value}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
            
            print("Final login token constructed successfully.")
            self.connect(final_token, 'anything', key, iv, whisper_ip, whisper_port, online_ip, online_port)
        except Exception as e:
            print(f"Error processing token: {e}")

# --- Program Execution ---

def restart_program():
    """Restarts the current program, closing open files and connections."""
    try:
        p = psutil.Process(os.getpid())
        for handler in p.open_files() + p.connections():
            try:
                os.close(handler.fd)
            except Exception:
                pass
        python = sys.executable
        os.execl(python, python, *sys.argv)
    except Exception as e:
        print(f"Failed to restart program: {e}")

def run_client(id, password):
    print(f"Starting bot client for ID: {id}")
    try:
        client = FF_CLIENT(id, password)
        client.start()
    except Exception as e:
        print(f"An error occurred while running client for {id}: {e}")

if __name__ == "__main__":
    try:
        with open('GHOST-X.json', 'r') as file:
            accounts = json.load(file)
    except FileNotFoundError:
        print("Error: 'GHOST-X.json' not found. Please create it with your account credentials.")
        sys.exit(1)
        
    ids_passwords = list(accounts.items())
    threads = []

    # Running one bot instance as per the original script's structure
    if ids_passwords:
        id, password = ids_passwords[0] # Using the first account from the json
        thread = threading.Thread(target=run_client, args=(id, password))
        threads.append(thread)
        thread.start()
    else:
        print("No accounts found in 'GHOST-X.json'.")

    for thread in threads:
        thread.join()