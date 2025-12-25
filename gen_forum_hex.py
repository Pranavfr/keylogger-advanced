
import binascii

def xor_enc(data, key):
    encrypted = bytearray()
    key_bytes = key.encode('utf-8')
    data_bytes = data.encode('utf-8')
    
    for i in range(len(data_bytes)):
        encrypted.append(data_bytes[i] ^ key_bytes[i % len(key_bytes)])
    
    return binascii.hexlify(encrypted).decode('utf-8')

# New Forum Channel Webhook
url = "https://discord.com/api/webhooks/1453457035138961591/1RmgOridgcYqYr0mVduh55O2WOGekvTcg7C8OFb-GH7gDVd7gTiMPise8_kqkexHl6k1"
key = "stark_industries_v3"

hex_str = xor_enc(url, key)
with open("forum_hex_output.txt", "w") as f:
    f.write(hex_str)
print("Hex saved to forum_hex_output.txt")
