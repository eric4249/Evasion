# Define the key
key = b"secret"
key_len = len(key)

# Read the source binary file
with open("meter.bin", "rb") as f:
  data = f.read()

# XOR each byte with the key
encrypted_data = bytes(b ^ key[i % key_len] for i, b in enumerate(data))

# Write the encrypted data to a new .bin file
with open("encrypted_meter.bin", "wb") as f:
  f.write(encrypted_data)

print("Encrypted binary file created: encrypted_meter.bin")
