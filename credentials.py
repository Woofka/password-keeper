import pickle
import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256


class CredentialsItem:
    def __init__(self, item_id, title, login, password, description, tags):
        self.id = item_id
        self.title = title
        self.login = login
        self.password = password
        self.description = description
        self.tags = tags

    def to_list(self):
        return [self.id, self.title, self.login, self.password, self.description, self.tags]

    @staticmethod
    def from_list(_list):
        return CredentialsItem(*_list)


class Credentials:
    def __init__(self, password):
        self._key = self.sha256(password)
        self._storage_file = 'data.pk'
        self._last_id = 0
        self._data = {}

    def remove_credentials(self, credentials_item: CredentialsItem):
        if credentials_item.id in self._data:
            del self._data[credentials_item.id]
            self.save_data()

    def update_credentials(self, credentials_item: CredentialsItem):
        if credentials_item.id is None:
            self._last_id += 1
            credentials_item.id = self._last_id
        self._data[credentials_item.id] = credentials_item
        self.save_data()

    def get_all_credentials(self):
        return list(self._data.values())

    def get_credentials(self, item_id):
        credentials = self._data.get(item_id, None)
        return credentials

    @staticmethod
    def sha256(text: str):
        return SHA3_256.new(text.encode('utf-8')).digest()

    @staticmethod
    def _encrypt_data(data: bytes, key: bytes):
        try:
            cipher = AES.new(key, AES.MODE_EAX)
            cipher_text, tag = cipher.encrypt_and_digest(data)
        except Exception as err:
            raise RuntimeError(f'Could not encrypt text. {err}')
        return cipher.nonce + tag + cipher_text

    @staticmethod
    def _decrypt_data(encrypted_data: bytes, key: bytes):
        try:
            nonce = encrypted_data[:16]
            tag = encrypted_data[16:32]
            cipher_text = encrypted_data[32:]
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(cipher_text, tag)
        except Exception as err:
            raise RuntimeError(f'Could not decrypt text. {err}')
        return data

    def save_data(self):
        try:
            credentials_data = []
            for credentials_item in self._data.values():
                credentials_data.append(credentials_item.to_list())
            data = [self._last_id, credentials_data]

            pickled_data = pickle.dumps(data)
            encrypted_data = self._encrypt_data(pickled_data, self._key)
            with open(self._storage_file, 'wb') as f:
                f.write(encrypted_data)
            return True
        except:
            return False

    def load_data(self):
        if not os.path.exists(self._storage_file):
            return
        with open(self._storage_file, 'rb') as f:
            encrypted_data = f.read()

        pickled_data = self._decrypt_data(encrypted_data, self._key)
        data = pickle.loads(pickled_data)

        self._last_id = data[0]
        credentials_data = data[1]
        for credentials_item_list in credentials_data:
            credentials_item = CredentialsItem.from_list(credentials_item_list)
            self._data[credentials_item.id] = credentials_item
