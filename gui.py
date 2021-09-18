import sys

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import (QApplication, QWidget, QDesktopWidget, QLabel, QMainWindow, QPushButton, QLineEdit,
                             QDialog, QGridLayout, QSpacerItem, QTableWidget, QTableWidgetItem, QFileDialog,
                             QInputDialog, QMessageBox, QTableView)

from credentials import Credentials, CredentialsItem


class PasswordTableWidget(QTableWidgetItem):
    def __init__(self, password=None):
        super().__init__('********')
        self.is_visible = False
        self.password = password

    def switch_visibility(self):
        self.is_visible = not self.is_visible
        if self.is_visible:
            self.setText(self.password)
        else:
            self.setText('********')


class CredentialsTableWidget(QTableWidgetItem):
    def __init__(self, credentials_item: CredentialsItem):
        super().__init__()
        self.credentials_item = credentials_item


class CredentialsDialog(QDialog):
    def __init__(self, parent: QWidget = None, credentials_item: CredentialsItem = None):
        super().__init__(parent=parent, flags=Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.credentials_item = credentials_item
        self.add_version = credentials_item is None
        self._init_ui()

    def _init_ui(self):
        self.title_label = QLabel('Title')
        self.title_text = QLineEdit()

        self.login_label = QLabel('Login')
        self.login_text = QLineEdit()

        self.password_label = QLabel('Password')
        self.password_text = QLineEdit()

        self.description_label = QLabel('Description')
        self.description_text = QLineEdit()

        self.tags_label = QLabel('Tags')
        self.tags_text = QLineEdit()

        if self.add_version:
            self.setWindowTitle('Add')
            self.title_text.setPlaceholderText('Title')
            self.login_text.setPlaceholderText('Login')
            self.password_text.setPlaceholderText('Password')
            self.description_text.setPlaceholderText('Description')
            self.tags_text.setPlaceholderText('tag1,tag2,tag3')
            self.id_label = QLabel('ID: None')
            self.save_btn = QPushButton('Add')
        else:
            self.setWindowTitle('Edit')
            self.title_text.setText(self.credentials_item.title)
            self.login_text.setText(self.credentials_item.login)
            self.password_text.setText(self.credentials_item.password)
            self.description_text.setText(self.credentials_item.description)
            self.tags_text.setText(self.credentials_item.tags)
            self.id_label = QLabel(f'ID: {self.credentials_item.id}')
            self.save_btn = QPushButton('Save')

        self.save_btn.clicked.connect(self.accept)

        self.id_label.setStyleSheet('color: grey')

        grid = QGridLayout()
        grid.setSpacing(5)

        grid.addWidget(self.title_label, 0, 0)
        grid.addWidget(self.title_text, 1, 0, 1, 0)
        grid.addWidget(self.login_label, 2, 0)
        grid.addWidget(self.login_text, 3, 0, 1, 0)
        grid.addWidget(self.password_label, 4, 0)
        grid.addWidget(self.password_text, 5, 0, 1, 0)
        grid.addWidget(self.description_label, 6, 0)
        grid.addWidget(self.description_text, 7, 0, 1, 0)
        grid.addWidget(self.tags_label, 8, 0)
        grid.addWidget(self.tags_text, 9, 0, 1, 0)
        grid.addWidget(self.id_label, 10, 0)
        grid.addWidget(self.save_btn, 10, 1)

        self.setLayout(grid)

    def get_results(self):
        if self.exec_() == QDialog.Accepted:
            if self.add_version:
                credentials_item = CredentialsItem(
                    None,
                    self.title_text.text(),
                    self.login_text.text(),
                    self.password_text.text(),
                    self.description_text.text(),
                    self.tags_text.text()
                )
                return credentials_item
            else:
                self.credentials_item.title = self.title_text.text()
                self.credentials_item.login = self.login_text.text()
                self.credentials_item.password = self.password_text.text()
                self.credentials_item.description = self.description_text.text()
                self.credentials_item.tags = self.tags_text.text()
                return self.credentials_item
        else:
            return None


class Gui(QMainWindow):
    def __init__(self):
        super().__init__()
        self.credentials = None
        self._init_ui()

    def _init_ui(self):
        self.resize(600, 400)
        self.setMinimumWidth(600)
        self.setMinimumHeight(400)

        qt_rect = self.frameGeometry()
        center = QDesktopWidget().availableGeometry().center()
        qt_rect.moveCenter(center)
        self.move(qt_rect.topLeft())

        self.setWindowTitle('Password Keeper')
        self.setWindowIcon(QIcon('AppIcon.ico'))

        self.statusBar()

        self.btn_add = QPushButton('Add')
        self.btn_add.clicked.connect(self._add)

        self.btn_edit = QPushButton('Edit')
        self.btn_edit.clicked.connect(self._edit)
        self.btn_edit.setEnabled(False)

        self.btn_remove = QPushButton('Remove')
        self.btn_remove.clicked.connect(self._remove)
        self.btn_remove.setEnabled(False)

        self.table_selection = None
        self.table = QTableWidget()
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.setColumnCount(6)
        self.table.verticalHeader().hide()
        self.table.setHorizontalHeaderLabels(['Title', 'Login', 'Password', 'Description', 'Tags', 'Item'])
        self.table.setColumnHidden(5, True)
        self.table.selectionModel().selectionChanged.connect(self._table_selection_changed)
        self.table.cellClicked.connect(self._table_password_click)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        grid = QGridLayout()
        grid.setSpacing(5)

        grid.addWidget(self.btn_add, 0, 0)
        grid.addWidget(self.btn_edit, 0, 1)
        grid.addWidget(self.btn_remove, 0, 2)
        grid.addItem(QSpacerItem(1, 5), 1, 0)

        grid.addWidget(self.table, 7, 0, 1, 3)
        grid.setRowStretch(7, 1)

        self.widget = QWidget(self)
        self.widget.setLayout(grid)
        self.setCentralWidget(self.widget)

        self.show()

    def _add(self):
        dialog = CredentialsDialog(self)
        credentials_item = dialog.get_results()
        if credentials_item is not None:
            self.credentials.update_credentials(credentials_item)
            self._add_table_row(credentials_item)

    def _edit(self):
        if self.table_selection is not None:
            credentials_item = self.table.item(self.table_selection, 5).credentials_item
            dialog = CredentialsDialog(self, credentials_item)
            credentials_item = dialog.get_results()
            self.credentials.update_credentials(credentials_item)
            self._update_table_row(self.table_selection, credentials_item)

    def _remove(self):
        if self.table_selection is not None:
            credentials_item = self.table.item(self.table_selection, 5).credentials_item
            self.table.removeRow(self.table_selection)
            self.credentials.remove_credentials(credentials_item)

    def _table_selection_changed(self, selected, deselected):
        if len(selected.indexes()) > 0:
            self.table_selection = selected.indexes()[0].row()
            self.btn_remove.setEnabled(True)
            self.btn_edit.setEnabled(True)
        else:
            self.btn_remove.setEnabled(False)
            self.btn_edit.setEnabled(False)

    def _table_password_click(self, row, column):
        if isinstance(self.table.item(row, column), PasswordTableWidget):
            self.table.item(row, column).switch_visibility()

    def _add_table_row(self, credentials_item: CredentialsItem):
        n = self.table.rowCount()
        self.table.setRowCount(n+1)
        self.table.setItem(n, 0, QTableWidgetItem(credentials_item.title))
        self.table.setItem(n, 1, QTableWidgetItem(credentials_item.login))
        self.table.setItem(n, 2, PasswordTableWidget(credentials_item.password))
        self.table.setItem(n, 3, QTableWidgetItem(credentials_item.description))
        self.table.setItem(n, 4, QTableWidgetItem(credentials_item.tags))
        self.table.setItem(n, 5, CredentialsTableWidget(credentials_item))

    def _update_table_row(self, row, credentials_item: CredentialsItem):
        self.table.setItem(row, 0, QTableWidgetItem(credentials_item.title))
        self.table.setItem(row, 1, QTableWidgetItem(credentials_item.login))
        self.table.setItem(row, 2, PasswordTableWidget(credentials_item.password))
        self.table.setItem(row, 3, QTableWidgetItem(credentials_item.description))
        self.table.setItem(row, 4, QTableWidgetItem(credentials_item.tags))
        self.table.setItem(row, 5, CredentialsTableWidget(credentials_item))

    def link_credentials(self, credentials: Credentials):
        self.credentials = credentials
        try:
            self.credentials.load_data()
        except:
            return False
        list_of_credentials = self.credentials.get_all_credentials()
        if len(list_of_credentials) > 0:
            for credentials_item in list_of_credentials:
                self._add_table_row(credentials_item)
        return True


class App:
    def __init__(self, argv):
        self.app = QApplication(argv)
        self.gui = Gui()

    def run(self):
        exit_app = False
        while True:
            password, ok = QInputDialog.getText(self.gui, 'Decrypt', 'Enter the password', QLineEdit.Password,
                                                flags=Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
            if not ok:
                exit_app = True
                break
            credentials = Credentials(password)
            success = self.gui.link_credentials(credentials)
            if success:
                break
            else:
                msg = QMessageBox(self.gui)
                msg.setIcon(QMessageBox.Critical)
                msg.setWindowTitle('Decryption error')
                msg.setText('Wrong password. Try again.')
                msg.exec_()

        if exit_app:
            self.app.exit()
        else:
            self.app.exec_()


if __name__ == '__main__':
    app = App(sys.argv)
    app.run()
