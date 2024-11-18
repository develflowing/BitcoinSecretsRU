import itertools
import asyncio
import aiohttp
import time
import mysql.connector
import hashlib
import json
from itertools import product
from base58 import b58encode
from Crypto.Hash import RIPEMD160
from ecdsa import SECP256k1, SigningKey
from aiohttp import BasicAuth

# Конфигурация MySQL
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'password',
    'database': 'private'
}

# Параметры для подключения к RPC Electrum
rpc_user = 'user'
rpc_password = 'password'
rpc_port = 7777

# Semaphore для ограничения параллельных запросов
semaphore = asyncio.Semaphore(30)  # Ограничение на 30 параллельных запросов

# Файл для сохранения состояния
STATE_FILE = "state.json"

# Сохранение состояния
def save_state(state):
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f)
    except Exception as e:
        print(f"\rОшибка при сохранении состояния: {e}")

# Загрузка состояния
def load_state():
    try:
        with open(STATE_FILE, 'r') as f:
            state = json.load(f)
            print(f"\rЗагружено состояние: {state}")
            return state
    except FileNotFoundError:
        print("\rФайл состояния не найден, создается новый.")
        return {"last_index": 0}
    except Exception as e:
        print(f"\rОшибка при загрузке состояния: {e}")
        return {"last_index": 0}

# Преобразование фразы в приватный ключ
def phrase_to_hex_key(phrase, hex_length=64):
    phrase_bytes = phrase.encode('utf-8')
    hash_object = hashlib.sha256(phrase_bytes)
    hex_hash = hash_object.hexdigest()
    return hex_hash.ljust(hex_length, '0') if len(hex_hash) < hex_length else hex_hash[:hex_length]

# Генерация публичного ключа
def private_to_public(private_key_hex):
    private_key_bytes = bytes.fromhex(private_key_hex)
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    return (b'\x04' + vk.to_string()).hex()

# Генерация Bitcoin-адреса
def public_to_bitcoin_address(public_key_hex):
    public_key_bytes = bytes.fromhex(public_key_hex)
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    ripemd160 = RIPEMD160.new()
    ripemd160.update(sha256_hash)
    hashed_public_key = ripemd160.digest()
    versioned_key = b'\x00' + hashed_public_key
    checksum = hashlib.sha256(hashlib.sha256(versioned_key).digest()).digest()[:4]
    return b58encode(versioned_key + checksum).decode()

# Генерация фраз по заданным символам и длине
def generate_phrases(symbols, length, start_index=0):
    combinations = list(itertools.product(symbols, repeat=length))
    total_combinations = len(combinations)  # Общее количество фраз
    for idx, phrase in enumerate(combinations):
        if idx < start_index:
            continue
        # Выводим процент выполнения
        percent = (idx / total_combinations) * 100
        print(f"\rОбработано: {idx}/{total_combinations} ({percent:.2f}%)", end="")
        yield idx, ''.join(phrase)  # Возвращаем индекс и фразу
    print()  # Переход на новую строку после завершения генерации

# Получение nonce
async def get_nonce(session, url, wallet_address):
    async with semaphore:
        json_data = {
            "id": 1,
            "method": "getaddresshistory",
            "params": [wallet_address]
        }
        try:
            async with session.post(url, json=json_data, auth=BasicAuth(rpc_user, rpc_password)) as response:
                if response.status == 200:
                    data = await response.json()
                    if 'result' in data:
                        nonce = len(data['result'])  # Количество транзакций
                        return wallet_address, nonce
                    else:
                        return wallet_address, 10000
                else:
                    print(f"\rОшибка для адреса {wallet_address}: {response.status}, {await response.text()}")
                    return wallet_address, None
        except Exception as e:
            print(f"\rОшибка при выполнении запроса для {wallet_address}: {e}")
            return wallet_address, None  # Вернуть None в случае ошибки

# Обновленная функция для более точного и стабильного вывода прогресса
def print_progress(total_processed, total_combinations, speed, last_batch_time):
    percent = (total_processed / total_combinations) * 100
    print(f"\rОбработано: {total_processed}/{total_combinations} ({percent:6.2f}%) "
          f"Средняя скорость: {speed:7.2f} адресов/сек. Время последнего батча: {last_batch_time:.2f} сек.", end="")

# Обновляем process_addresses для замера времени
async def process_addresses(symbols, length, batch_size=1000):
    url = f'http://localhost:{rpc_port}'
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    # Загружаем состояние
    state = load_state()
    last_index = state.get("last_index", 0)

    # Инициализируем генератор фраз
    phrases = generate_phrases(symbols, length, start_index=last_index)
    
    total_combinations = len(list(itertools.product(symbols, repeat=length)))  # Общее количество фраз
    total_processed = 0  # Счётчик обработанных адресов
    total_time = 0  # Суммарное время обработки
    last_batch_time = 0

    while True:
        start_time = time.time()
        addresses = []

        # Генерация адресов
        for _ in range(batch_size):
            try:
                index, phrase = next(phrases)
                private_key = phrase_to_hex_key(phrase)
                public_key = private_to_public(private_key)
                address = public_to_bitcoin_address(public_key)
                addresses.append((index, phrase, address, private_key))
            except StopIteration:
                print("\rГенерация завершена.")
                break

        if not addresses:
            print("\rВсе фразы обработаны.")
            break

        # Асинхронные запросы для получения nonce
        async with aiohttp.ClientSession() as session:
            tasks = [get_nonce(session, url, addr) for _, _, addr, _ in addresses]
            results = await asyncio.gather(*tasks)

        updates = []
        for (index, phrase, address, private_key), (_, nonce) in zip(addresses, results):
            if nonce is not None:
                updates.append((phrase, address, nonce, private_key))

        if updates:
            # Фильтруем обновления, оставляем только те, у которых nonce > 0
            filtered_updates = [(phrase, address, nonce, private_key) for phrase, address, nonce, private_key in updates if nonce > 0]

            if filtered_updates:
                try:
                    cursor.executemany(
                        "INSERT IGNORE INTO brainwallet (phrase, btc, btc_nonce, privateHEX) VALUES (%s, %s, %s, %s)",
                        filtered_updates,
                    )
                    conn.commit()
                    print(f"\rСохранено {len(filtered_updates)} записей с положительным nonce в базу данных.")
                except Exception as db_error:
                    print(f"\rОшибка базы данных: {db_error}")
                    conn.rollback()

        # Обновляем индекс состояния после обработки текущего батча
        last_index = addresses[-1][0] + 1  # Обновляем на последний обработанный индекс + 1
        save_state({"last_index": last_index})

        # Подсчёт скорости обработки
        end_time = time.time()
        batch_time = end_time - start_time
        total_time += batch_time
        total_processed += len(addresses)
        speed = total_processed / total_time  # Скорость обработки (адресов в секунду)

        # Выводим процент, количество адресов и скорость
        average_speed = total_processed / (end_time - start_time)  # Средняя скорость
        print_progress(total_processed, total_combinations, average_speed, batch_time)

    print()  # Переход на новую строку после завершения
    
# Обертка для запуска асинхронной функции
def main():
    symbols = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '
    length = 4
    asyncio.run(process_addresses(symbols, length))  # Запуск асинхронной функции

# Запуск программы
if __name__ == "__main__":
    main()