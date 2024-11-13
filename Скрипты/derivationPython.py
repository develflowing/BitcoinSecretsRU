# Код производитдеривaцию ключей (или деривацию дочерних ключей из мастер-ключа). 
# В частности, для криптографических кошельков и блокчейнов, таких как Bitcoin, этот процесс формализован в стандарте BIP-32 и называется иерархической детерминированной (HD) деривацией ключей.
# HD-деривация позволяет из одного мастер-ключа (называемого "seed" или "начальное зерно") безопасно и предсказуемо генерировать иерархию дочерних ключей. Это позволяет пользователю:
# Управлять множеством адресов из одного мастер-ключа, что удобно для резервного копирования (достаточно хранить только seed-фразу).
# Создавать новые ключи и адреса для транзакций, сохраняя при этом связь с исходным мастер-ключом, и возможность воссоздать все дочерние ключи при необходимости.
# Мастер-ключ (Master Key): Начальный ключ, от которого строится вся иерархия.
# Дочерние ключи (Child Keys): Ключи, сгенерированные от мастер-ключа.
# Путь деривации (Derivation Path): Последовательность индексов, описывающая путь к определённому дочернему ключу (например, m/0'/0/1).
# Используя HMAC-SHA512 и мастер-ключ, можно получить предсказуемый набор дочерних ключей, и все они будут связаны и воспроизводимы.

import hmac
import hashlib
import base58
import sqlite3
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import string_to_number
from Crypto.Hash import RIPEMD160
from hashlib import sha3_256
import mysql.connector


# Подключение к базе данных
def create_connection():
    return mysql.connector.connect(
        host="localhost",   # Замените на ваши параметры
        user="root",        # Имя пользователя MySQL
        password="pass",        # Пароль MySQL
        database="private"  # Имя базы данных
    )

# Преобразование фразы в приватный ключ
def phrase_to_hex_key(phrase, hex_length=64):
    phrase_bytes = phrase.encode('utf-8')
    hash_object = hashlib.sha256(phrase_bytes)
    hex_hash = hash_object.hexdigest()
    return hex_hash.ljust(hex_length, '0') if len(hex_hash) < hex_length else hex_hash[:hex_length]

# Генерация публичного ключа из приватного ключа
def private_to_public(private_key_hex):
    private_key_bytes = bytes.fromhex(private_key_hex)
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    return (b'\x04' + vk.to_string()).hex()  # Публичный ключ в формате 04 + (x, y)

# Генерация Ethereum адреса
def public_to_ethereum_address(public_key_hex):
    public_key_bytes = bytes.fromhex(public_key_hex)
    keccak = sha3_256()
    keccak.update(public_key_bytes[1:])  # Берем только (x, y), без префикса 0x04
    return "0x" + keccak.hexdigest()[-40:]  # Последние 20 байт (40 символов)

# Генерация Bitcoin адреса
def public_to_bitcoin_address(public_key_hex):
    public_key_bytes = bytes.fromhex(public_key_hex)
    
    # Шаг 1: SHA-256 от публичного ключа
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    
    # Шаг 2: RIPEMD-160 от SHA-256
    ripemd160 = RIPEMD160.new()
    ripemd160.update(sha256_hash)
    hashed_public_key = ripemd160.digest()
    
    # Шаг 3: Добавление версии (0x00 для mainnet)
    versioned_key = b'\x00' + hashed_public_key
    
    # Шаг 4: SHA-256 два раза для контрольной суммы
    checksum = hashlib.sha256(hashlib.sha256(versioned_key).digest()).digest()[:4]
    
    # Шаг 5: Добавление контрольной суммы и base58
    return base58.b58encode(versioned_key + checksum).decode()

# Генерация дочернего приватного ключа из мастер-ключа
def generate_child_private_key(master_private_key, index):
    """
    Генерирует дочерний приватный ключ из мастер-ключа и индекса
    """
    # Преобразуем мастер-ключ в байты
    master_private_key_bytes = bytes(master_private_key, 'utf-8')

    # Индекс нужно преобразовать в байты (для этого используем 4 байта, т.к. индекс в пределах int32)
    index_bytes = index.to_bytes(4, byteorder='big')

    # Используем HMAC с SHA512 для вычисления дочернего ключа
    hmac_result = hmac.new(master_private_key_bytes, index_bytes, hashlib.sha512).digest()

    # Получаем 32 байта для приватного ключа (это стандартная длина для биткойн-ключей)
    child_private_key = hmac_result[:32]

    # Конвертируем в шестнадцатеричную строку для отображения
    return child_private_key.hex()

# Генерация множества ключей
def generate_keys(master_private_key, num_keys):
    """
    Генерирует несколько приватных ключей
    """
    keys = []
    for i in range(num_keys):
        child_key = generate_child_private_key(master_private_key, i)
        keys.append(child_key)
    return keys

# Обработка каждой фразы
def process_phrase(private_key):
    public_key = private_to_public(private_key)
    bitcoin_address = public_to_bitcoin_address(public_key)
    ethereum_address = public_to_ethereum_address(public_key)
    return (private_key, bitcoin_address, ethereum_address)

# Обновление базы данных
def update_database(connection, private_key, bitcoin_address, ethereum_address):
    cursor = connection.cursor()
    cursor.execute(
        "INSERT IGNORE INTO lcg (privateHEX, btc, eth) VALUES (%s, %s, %s)",
        (private_key, bitcoin_address, ethereum_address)
    )
    connection.commit()
    cursor.close()

# Основная функция обработки с сохранением в базу
def process_sql(master_private_key, num_keys=100000):
    connection = create_connection()  # Создаем одно подключение к базе данных
    
    # Генерация 1000 ключей
    keys = generate_keys(master_private_key, num_keys)

    for private_key in keys:
        result = process_phrase(private_key)  # Генерируем публичные ключи и адреса
        update_database(connection, result[0], result[1], result[2])  # Сохраняем в базу

    connection.close()  # Закрываем соединение после завершения обработки

# Запуск программы
if __name__ == "__main__":
    master_private_key = "000000000000000000000000000000000000000000000000000000000000001"  # Это ваш мастер-ключ (в реальности это длинная строка, например, 64 символа)
    process_sql(master_private_key)  # Запускаем основной процесс
   
