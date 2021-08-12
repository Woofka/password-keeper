import os
import sys
import pickle
import argparse

import pandas as pd
from prettytable import PrettyTable
from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256


def put_in_clipboard(text: str):
    if sys.platform == 'win32':
        import win32clipboard as clip
        clip.OpenClipboard()
        clip.EmptyClipboard()
        clip.SetClipboardText(text, clip.CF_UNICODETEXT)
        clip.CloseClipboard()
    else:
        raise RuntimeError(f'Unsupported platform: {sys.platform}')


def sha256(text: str):
    return SHA3_256.new(text.encode('utf-8')).digest()


def encrypt_data(data: bytes, key: bytes):
    try:
        cipher = AES.new(key, AES.MODE_EAX)
        cipher_text, tag = cipher.encrypt_and_digest(data)
    except Exception as err:
        raise RuntimeError(f'Could not encrypt text. {err}')
    return cipher.nonce + tag + cipher_text


def decrypt_data(encrypted_data: bytes, key: bytes):
    try:
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        cipher_text = encrypted_data[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(cipher_text, tag)
    except Exception as err:
        raise RuntimeError(f'Could not decrypt text. {err}')
    return data


class SoftArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise Exception(f'Error: {message}')


class PasswordKeeper:
    def __init__(self):
        self._storage_file = os.path.join(os.path.dirname(__file__), 'passkeeper.data')
        self._data = {
            'last_id': -1,
            'tags': {},
            'data': {}
        }
        self._key = None
        self._is_running = True

    @staticmethod
    def _y_n_confirmation(msg: str):
        try:
            while True:
                answ = input(f'{msg} [y/n]: ')
                if answ.lower() in ('y', 'yes'):
                    return True
                elif answ.lower() in ('n', 'no'):
                    return False
                else:
                    print(f'Incorrect answer: \'{answ}\'. Type \'y\' (yes) or \'n\' (no) instead.')
                    continue
        except KeyboardInterrupt:
            return None

    @staticmethod
    def _input_password(msg):
        os.system('echo off')
        os.system(
            f'powershell -Command $pword = read-host "{msg}" -AsSecureString ; $BSTR=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pword) ; [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) > .tmp.txt')
        with open('.tmp.txt', 'r') as f:
            password = f.readline().replace('\n', '')
        os.remove('.tmp.txt')
        os.system('echo on')
        return password

    def _get_key(self, msg='Input'):
        tries = 0
        while True:
            if tries >= 3:
                answ = self._y_n_confirmation('Something went wrong. Do you want to continue?')
                if answ is None:
                    exit(1)
                elif answ:
                    tries = 0
                    continue
                else:
                    print('Ok. Exiting than...')
                    exit(0)
            tries += 1

            password = self._input_password(f'[Attempt: {tries}/3] {msg}')
            if ' ' in password:
                print('Key should not contain spaces.')
                continue
            if len(password) == 0:
                print('Key should not be empty')
                continue

            return sha256(password)

    def _load_encrypted_data(self):
        if not os.path.exists(self._storage_file):
            print(f'File {self._storage_file} does not exist.')
            answ = self._y_n_confirmation('Do you want to create new one?')
            if answ is None:
                exit(1)
            elif answ:
                with open(self._storage_file, 'wb'):
                    pass
            else:
                print('Ok. Exiting than...')
                exit(0)

        with open(self._storage_file, 'rb') as f:
            encrypted_data = f.read()
        return encrypted_data

    def _load_data(self):
        encrypted_data = self._load_encrypted_data()
        if len(encrypted_data) == 0:
            answ = self._y_n_confirmation('The data file is empty. Do you want to create a new key for it?')
            if answ is None:
                exit(1)
            elif answ:
                self._key = self._get_key('Enter a new key for the data file')
                return
            else:
                print('Ok. Exiting than...')
                exit(0)
        else:
            attempts = 0
            while True:
                if attempts >= 3:
                    answ = self._y_n_confirmation('Something went wrong. Do you want to continue?')
                    if answ is None:
                        exit(1)
                    elif answ:
                        attempts = 0
                        continue
                    else:
                        print('Ok. Exiting than...')
                        exit(0)
                attempts += 1

                self._key = self._get_key('Enter the key for the data file')
                try:
                    pickled_data = decrypt_data(encrypted_data, self._key)
                    self._data = pickle.loads(pickled_data)
                    print('Data file was successfully loaded')
                    return
                except:
                    print('Could not decrypt data. Try again.')
                    continue

    def _save_data(self):
        try:
            pickled_data = pickle.dumps(self._data)
            encrypted_data = encrypt_data(pickled_data, self._key)
            with open(self._storage_file, 'wb') as f:
                f.write(encrypted_data)
            return True
        except:
            return False

    def _tags_cmd(self):
        if len(self._data['tags']) == 0:
            print('No tags to show.')
            return
        pt = PrettyTable()
        pt.field_names = ['Tag', 'Records']
        tags = list(self._data['tags'].keys())
        tags.sort()
        for t in tags:
            pt.add_row([t, self._data['tags'][t]])
        pt.align = 'l'
        print(pt)

    def _add_cmd(self, cmd: str):
        parser = SoftArgumentParser(
            prog='add',
            description='Add new record'
        )
        parser.add_argument(
            '-d',
            '--description',
            default=[],
            nargs='*',
            help='Description of a record.'
        )
        parser.add_argument(
            '--tags',
            metavar='TAG',
            default=[],
            nargs='*',
            help='List of tags for a record',
        )
        parser.add_argument(
            '-p',
            '--password',
            metavar='PASSWORD',
            default=None,
            help='Password. It is not safe to use. Better to run command without it and enter password later.'
        )
        parser.add_argument(
            '--title',
            metavar='TITLE',
            nargs='+',
            required=True,
            help='Title of a record.'
        )
        parser.add_argument(
            '-l',
            '--login',
            metavar='LOGIN',
            required=True,
            help='Login.'
        )
        if '-h' in cmd or '--help' in cmd:
            parser.print_help()
            return
        try:
            args = parser.parse_args(cmd.split()[1:])
        except Exception as err:
            print(err)
            return
        title = ' '.join(args.title)
        login = args.login
        if len(args.description) > 0:
            descr = ' '.join(args.description)
        else:
            descr = ''
        if len(args.tags) > 0:
            tags = []
            for t in args.tags:
                if ';' in t:
                    print('Tag should not contain symbol \';\'')
                    return
                tags.append(t.lower())
        else:
            tags = []
        if args.password is not None:
            password = args.password
        else:
            pass1 = None
            attempts = 0
            while True:
                if attempts >= 3:
                    answ = self._y_n_confirmation('Something went wrong. Do you want to continue?')
                    if answ is None or not answ:
                        print('Record was not saved.')
                        return
                    elif answ:
                        attempts = 0
                        pass1 = None
                        continue
                attempts += 1

                if pass1 is None:
                    pass1 = self._input_password('Enter the password')

                pass2 = self._input_password('Enter the password again')
                if pass1 == pass2:
                    password = pass1
                    break
                else:
                    print('Passwords do not match.')
                    continue

        record = {
            'title': title,
            'login': login,
            'password': password,
            'tags': tags,
            'description': descr
        }
        res = self._add_record(record)
        if res:
            print('Record was successfully added.')
        else:
            print('Something went wrong and record was not saved.')

    def _add_record(self, record):
        self._data['last_id'] += 1
        new_data_id = self._data['last_id']
        record['id'] = new_data_id
        if len(record['tags']) == 0:
            record['tags'] = ['<without tags>']
        for t in record['tags']:
            if t not in self._data['tags']:
                self._data['tags'][t] = 1
            else:
                self._data['tags'][t] += 1
        self._data['data'][new_data_id] = record
        return self._save_data()

    def _remove_cmd(self, cmd):
        parser = SoftArgumentParser(
            prog='remove',
            description='Remove a record.'
        )
        parser.add_argument(
            'id',
            metavar='ID',
            type=int,
            help='ID of a record to remove.'
        )
        if '-h' in cmd or '--help' in cmd:
            parser.print_help()
            return
        try:
            args = parser.parse_args(cmd.split()[1:])
        except Exception as err:
            print(err)
            return

        res = self._remove_data(args.id)
        if res:
            print(f'Record was successfully removed.')
        else:
            print(f'No record with id {args.id}.')

    def _remove_data(self, data_id):
        if data_id in self._data['data']:
            tags = self._data['data'][data_id]['tags']
            for t in tags:
                if t in self._data['tags']:
                    if self._data['tags'][t] <= 1:
                        del self._data['tags'][t]
                    else:
                        self._data['tags'][t] -= 1
            del self._data['data'][data_id]
            return self._save_data()
        return False

    def _print_list(self):
        if len(self._data['data']) == 0:
            print('No records to show.')
            return
        tags = list(self._data['tags'].keys())
        tags.sort()
        for tag in tags:
            rows = []
            for data_id, data in self._data['data'].items():
                if tag in data['tags']:
                    rows.append([data_id, data['title'], data['login'], data['description'], ', '.join(data['tags'])])
            if len(rows) > 0:
                pt = PrettyTable()
                pt.field_names = ['ID', 'Title', 'Login', 'Description', 'Tags']
                pt.title = tag.upper()
                pt.add_rows(rows)
                pt.align = 'l'
                print(pt.get_string(sortby='Title'))

    def _get_cmd(self, cmd):
        parser = SoftArgumentParser(
            prog='get',
            description='Get a password from specified record.'
        )
        parser.add_argument(
            'id',
            metavar='ID',
            type=int,
            help='ID of a record.'
        )
        parser.add_argument(
            '-p',
            '--print',
            action='store_true',
            help='Print password.'
        )
        if '-h' in cmd or '--help' in cmd:
            parser.print_help()
            return
        try:
            args = parser.parse_args(cmd.split()[1:])
        except Exception as err:
            print(err)
            return

        credentials = self._get_credentials(args.id)
        if credentials is not None:
            put_in_clipboard(credentials[1])
            print('Password was copied into clipboard buffer.')
            print(f'Login:    {credentials[0]}')
            if args.print:
                print(f'Password: {credentials[1]}')
            else:
                print('Password: ********')
        else:
            print(f'No record with id {args.id}.')

    def _get_credentials(self, data_id):
        if data_id in self._data['data']:
            data = self._data['data'][data_id]
            return data['login'], data['password']
        else:
            return None

    def _search_cmd(self, cmd):
        parser = SoftArgumentParser(
            prog='search',
            description='Search for records.'
        )
        parser.add_argument(
            'keywords',
            metavar='KEYWORD',
            nargs='+',
            help='Keywords for a search.'
        )
        if '-h' in cmd or '--help' in cmd:
            parser.print_help()
            return
        try:
            args = parser.parse_args(cmd.split()[1:])
        except Exception as err:
            print(err)
            return
        keywords = [i.lower() for i in args.keywords]
        self._search(keywords)

    def _search(self, keywords):
        rows = []
        for data_id, data in self._data['data'].items():
            for word in keywords:
                if word in data['title'].lower() \
                        or word in data['tags'] \
                        or word in data['description'].lower().split():
                    rows.append([data_id, data['title'], data['login'], data['description'], ', '.join(data['tags'])])
                    break
        pt = PrettyTable()
        pt.field_names = ['ID', 'Title', 'Login', 'Description', 'Tags']
        pt.add_rows(rows)
        pt.align = 'l'
        print(pt.get_string(sortby='Title'))

    def _load_cmd(self, cmd):
        parser = SoftArgumentParser(
            prog='load',
            description='Load decrypted data from csv file.'
        )
        parser.add_argument(
            'path',
            nargs='?',
            metavar='PATH',
            help='File path.'
        )
        if '-h' in cmd or '--help' in cmd:
            parser.print_help()
            return
        try:
            args = parser.parse_args(cmd.split()[1:])
        except Exception as err:
            print(err)
            return
        path = args.path
        if path is None:
            path = os.path.join(os.path.dirname(__file__), 'passkeeper_dump.csv')
        if not os.path.exists(path):
            print(f'No such file {path}')

        df = pd.read_csv(path, sep=',')
        df['description'].fillna('', inplace=True)
        for _, row in df.iterrows():
            record = {
                'title': row.title,
                'login': row.login,
                'password': row.password,
                'tags': row.tags.split(';'),
                'description': row.description
            }
            self._add_record(record)

    def _dump_cmd(self, cmd):
        parser = SoftArgumentParser(
            prog='dump',
            description='Save decrypted data as csv file.'
        )
        parser.add_argument(
            'path',
            nargs='?',
            metavar='PATH',
            help='File path.'
        )
        if '-h' in cmd or '--help' in cmd:
            parser.print_help()
            return
        try:
            args = parser.parse_args(cmd.split()[1:])
        except Exception as err:
            print(err)
            return
        path = args.path
        if path is None:
            path = os.path.join(os.path.dirname(__file__), 'passkeeper_dump.csv')
        if os.path.exists(path):
            print(f'File {path} already exists.')
            answ = self._y_n_confirmation('Do you want to overwrite it?')
            if answ is None or not answ:
                return

        df = pd.DataFrame(self._data['data'])
        df = df.transpose()
        df['tags'] = df['tags'].apply(lambda x: ';'.join(x))
        df.drop(columns=['id'], inplace=True)
        try:
            df.to_csv(path, index=False, sep=',')
            print(f'Data was successfully saved in {path}')
        except:
            print(f'Could not save data in {path}')

    def run(self):
        self._load_data()
        records_num = len(self._data['data'])
        print(f'Current records number: {records_num}')
        while True:
            cmd = input('> ').lower().strip()
            if cmd == 'exit':
                return
            elif cmd == 'help':
                print('Next commands allowed:\n'
                      'exit   - close this program\n'
                      'help   - show this message\n'
                      'tags   - show info about used tags\n'
                      'search - search for records\n'
                      'get    - get a credentials\n'
                      'add    - add a new record\n'
                      'remove - remove a record\n'
                      'list   - show all records\n'
                      'dump   - save decrypted data as csv file\n'
                      'load   - load decrypted data from csv file')
                continue
            elif cmd.startswith('search'):
                self._search_cmd(cmd)
            elif cmd.startswith('add'):
                self._add_cmd(cmd)
            elif cmd.startswith('remove'):
                self._remove_cmd(cmd)
            elif cmd == 'list':
                self._print_list()
            elif cmd.startswith('get'):
                self._get_cmd(cmd)
            elif cmd == 'tags':
                self._tags_cmd()
            elif cmd.startswith('dump'):
                self._dump_cmd(cmd)
            elif cmd.startswith('load'):
                self._load_cmd(cmd)
            elif cmd == '':
                pass
            else:
                print('Wrong command.')


def main():
    pk = PasswordKeeper()
    pk.run()


if __name__ == '__main__':
    main()
