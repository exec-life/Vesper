import discord
import os
import requests
import json
import socket
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from io import BytesIO
import base64
import zlib
from scapy.all import *


#Bot Setup
client = discord.Client()

#Utility Functions
def get_ip_from_msg(msg):
    hostname = msg[4:]
    try:
        resp = socket.gethostbyname(hostname)
        return resp
    except Exception as e:
        resp = f"Unable to fetch IP: {e}"
        return resp

def get_host_from_msg(msg):
    ip = msg[10:]
    try:
        resp = socket.gethostbyaddr(ip)[0]
        return resp
    except Exception as e:
        resp = f"Unable to fetch Host: {e}"
        return resp

def generate():
    try:
        new_key = RSA.generate(2048)
        private_key = new_key.exportKey()
        public_key = new_key.publickey().exportKey()

        with open('key.pri', 'wb') as f:
            f.write(private_key)
        with open('key.pub', 'wb') as f:
            f.write(public_key)
        resp = "Key successfully generated" 
        return resp
    except Exception as e:
        resp = f"Unable to Generate Encryption Key: {e}"
        return resp


def get_rsa_cipher(keytype):
    with open(f'key.{keytype}') as f:
        key = f.read()
    rsakey = RSA.importKey(key)
    return (PKCS1_OAEP.new(rsakey), rsakey.size_in_bytes())

def encrypt(msg):
    message = msg[9:]
    plaintext = bytes(message, 'utf-8')
    compressed_text = zlib.compress(plaintext)

    session_key = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(compressed_text)

    cipher_rsa, _ = get_rsa_cipher('pub')
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    msg_payload = encrypted_session_key + cipher_aes.nonce + tag + ciphertext
    encrypted = base64.encodebytes(msg_payload)
    enc_msg = encrypted.decode('utf-8')
    return enc_msg

def decrypt(msg):
    message = msg[9:]
    encrypted = bytes(message, 'utf-8')
    encrypted_bytes = BytesIO(base64.decodebytes(encrypted))
    cipher_rsa, keysize_in_bytes = get_rsa_cipher('pri')

    encrypted_session_key = encrypted_bytes.read(keysize_in_bytes)
    nonce = encrypted_bytes.read(16)
    tag = encrypted_bytes.read(16)
    ciphertext = encrypted_bytes.read()

    session_key = cipher_rsa.decrypt(encrypted_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)

    plaintext = zlib.decompress(decrypted)
    pln_msg = plaintext.decode('utf-8')
    return pln_msg

#Bot Actions
@client.event
async def on_ready():
    print(f"Logged in successfully as {client.user}")

@client.event
async def on_message(message):
    if message.author == client.user:
        return
    if message.content.startswith("ip? "):
        resp = get_ip_from_msg(message.content)
        await message.channel.send(resp)
    elif message.content.startswith("hostname? "):
        resp = get_host_from_msg(message.content)
        await message.channel.send(resp)
    elif message.content.startswith("keygen?"):
        resp = generate()
        await message.channel.send(resp)
    elif message.content.startswith("encrypt? "):
        resp = encrypt(message.content)
        await message.channel.send(resp)
    elif message.content.startswith("decrypt? "):
        resp = decrypt(message.content)
        await message.channel.send(resp)

client.run("YOURTOKENHERE")