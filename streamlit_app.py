import streamlit as st

# Fungsi konversi teks ke biner dan sebaliknya
def text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary):
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    try:
        return ''.join(chr(int(char, 2)) for char in chars if len(char) == 8)
    except ValueError:
        return "Invalid binary for text conversion."

# Fungsi XOR, wrap kiri, dan wrap kanan
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
            block = block.zfill(block_size)
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

    plaintext = ''.join(decrypted_blocks).rstrip('0')
    plaintext_hex = hex(int(plaintext, 2))[2:].upper() if plaintext else "0"
    plaintext_text = binary_to_text(plaintext)

    return plaintext_text, plaintext_hex, process

# Streamlit Interface


st.title("🎈 Enkripsi dan Dekripsi ECB")
st.write("Dibuat oleh ARIELLA RISQY MAULANA - A11.2022.14035 & BIMA NUR ABDILLAH - A11.2022.14041")
st.write("TUGAS KRIPTOGRAFI A11.4509")
st.write("Pilih opsi untuk melakukan enkripsi atau dekripsi dan masukkan plaintext serta key.")

# Tata letak horizontal
with st.container():
    col1, col2, col3 = st.columns([1, 2, 1])  # Pengaturan lebar kolom

    with col1:
        st.subheader("Input dan Proses")
        plaintext_input = st.text_input("Masukkan Plaintext (biner atau teks biasa):", "Hello")
        key = st.text_input("Masukkan Key (dalam bentuk biner):", "1010")

        operation = st.radio("Pilih operasi:", ("Enkripsi", "Dekripsi"))

        if st.button("Proses"):
            if operation == "Enkripsi":
                if not all(c in '01' for c in plaintext_input):  # Deteksi input teks biasa
                    plaintext_binary = text_to_binary(plaintext_input)
                else:
                    plaintext_binary = plaintext_input

                ciphertext, ciphertext_hex, encrypt_process = ecb_encrypt(plaintext_binary, key)
                st.session_state["output"] = {
                    "steps": encrypt_process,
                    "binary_result": ciphertext,
                    "hex_result": ciphertext_hex,
                    "operation": "Enkripsi",
                }

            elif operation == "Dekripsi":
                plaintext_text, plaintext_hex, decrypt_process = ecb_decrypt(plaintext_input, key)
                st.session_state["output"] = {
                    "steps": decrypt_process,
                    "binary_result": plaintext_input,
                    "text_result": plaintext_text,
                    "hex_result": plaintext_hex,
                    "operation": "Dekripsi",
                }

    with col2:
        st.subheader("Langkah-langkah")
        if "output" in st.session_state:
            output = st.session_state["output"]
            for step in output["steps"]:
                st.write(step)

    with col3:
        st.subheader("Hasil Akhir")
        if "output" in st.session_state:
            output = st.session_state["output"]
            if output["operation"] == "Enkripsi":
                st.write("Ciphertext (biner):", output["binary_result"])
                st.write("Ciphertext (Hexadecimal):", output["hex_result"])
            elif output["operation"] == "Dekripsi":
                st.write("Decrypted Plaintext (biner):", output["binary_result"])
                st.write("Decrypted Plaintext (teks):", output["text_result"])
                st.write("Decrypted Plaintext (Hexadecimal):", output["hex_result"])
