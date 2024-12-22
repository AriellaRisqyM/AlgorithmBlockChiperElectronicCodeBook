import streamlit as st

# Fungsi XOR, wrap kiri, dan wrap kanan yang sudah ada
def xor_operation(block, key):
    return ''.join(str(int(b) ^ int(k)) for b, k in zip(block, key))

def wrap_right(block, shift=1):
    return block[-shift:] + block[:-shift]

def wrap_left(block, shift=1):
    return block[shift:] + block[:shift]

# Fungsi enkripsi ECB
def ecb_encrypt(plaintext, key):
    block_size = len(key)
    blocks = [plaintext[i:i+block_size] for i in range(0, len(plaintext), block_size)]
    encrypted_blocks = []
    process = []

    for block in blocks:
        if len(block) < block_size:
            block = block.ljust(block_size, '0')
        step_info = f"Original Block: {block}"
        encrypted = xor_operation(block, key)
        step_info += f" -> After XOR: {encrypted}"
        encrypted = wrap_left(encrypted)
        step_info += f" -> After Wrap: {encrypted}"
        encrypted_blocks.append(encrypted)
        process.append(step_info)

    ciphertext = ''.join(encrypted_blocks)
    return ciphertext, hex(int(ciphertext, 2))[2:].upper(), process

# Fungsi dekripsi ECB
def ecb_decrypt(ciphertext, key):
    block_size = len(key)
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    decrypted_blocks = []
    process = []

    for block in blocks:
        step_info = f"Ciphertext Block: {block}"
        block = wrap_right(block)
        step_info += f" -> After Unwrap: {block}"
        decrypted = xor_operation(block, key)
        step_info += f" -> After XOR: {decrypted}"
        decrypted_blocks.append(decrypted)
        process.append(step_info)

    plaintext = ''.join(decrypted_blocks)
    plaintext_hex = hex(int(plaintext, 2))[2:].upper()  # Convert final plaintext to hex
    return plaintext.rstrip('0'), plaintext_hex, process

# Streamlit Interface
st.title("🎈 Enkripsi dan Dekripsi ECB")
st.write("Pilih opsi untuk melakukan enkripsi atau dekripsi dan masukkan plaintext dan key.")

# Input untuk plaintext dan key
plaintext = st.text_input("Masukkan Plaintext (dalam bentuk biner):", "1001001010111001")
key = st.text_input("Masukkan Key (dalam bentuk biner):", "1010")

# Pilihan mode: Enkripsi atau Dekripsi
operation = st.radio("Pilih operasi:", ("Enkripsi", "Dekripsi"))

# Tombol untuk memproses
if st.button("Proses"):
    if operation == "Enkripsi":
        ciphertext, ciphertext_hex, encrypt_process = ecb_encrypt(plaintext, key)
        st.subheader("Langkah-langkah Enkripsi:")
        for step in encrypt_process:
            st.write(step)
        st.write("\nCiphertext (biner):", ciphertext)
        st.write("Ciphertext (Hexadecimal):", ciphertext_hex)

    elif operation == "Dekripsi":
        plaintext_decrypted, plaintext_decrypted_hex, decrypt_process = ecb_decrypt(plaintext, key)
        st.subheader("Langkah-langkah Dekripsi:")
        for step in decrypt_process:
            st.write(step)
        st.write("\nDecrypted Plaintext (biner):", plaintext_decrypted)
        st.write("Decrypted Plaintext (Hexadecimal):", plaintext_decrypted_hex)
