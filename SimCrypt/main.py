import binascii
import os
import sys

from cryptography.fernet import InvalidToken
from kivy.app import App
from kivy.core.clipboard import Clipboard
from kivy.resources import resource_add_path
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.uix.textinput import TextInput

from backend import (aes128_decrypt, aes128_encrypt, base64_decode,
                     base64_encode, x25519_key_derive, x25519_key_gen)

__version__ = '0.1.0'
font = 'SourceHanSansCN-Regular.ttf'


def get_resource_path():
    '''Returns path containing content - either locally or in pyinstaller tmp file. Fix one-file generation.'''
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS)

    return os.path.join(os.path.abspath("."))


def copy(target):
    def callback(instance):
        Clipboard.copy(target.text)
    return callback


def paste(target):
    def callback(instance):
        target.text = Clipboard.paste()
    return callback


class X25519KeyExchange(GridLayout):
    def __init__(self, **kwargs):
        super(X25519KeyExchange, self).__init__(**kwargs)
        self.cols = 2

        def generate(instance=None):
            self.private, self.public = x25519_key_gen()
            self.token.text = self.public

        def calculate(instance, value):
            if value:
                try:
                    key = x25519_key_derive(self.private, value)
                    self.key.text = key
                except ValueError:
                    pass

        self.row1b = GridLayout(cols=1, size_hint_x=100, size_hint_y=10)
        self.regen = Button(text='重新生成', font_name=font)
        self.regen.bind(on_press=generate)
        self.row1b.add_widget(self.regen)
        self.copy_token = Button(text='复制代码', font_name=font)
        self.token = TextInput(readonly=True, size_hint_x=300, font_name=font)
        self.copy_token.bind(on_press=copy(self.token))
        self.row1b.add_widget(self.copy_token)
        self.add_widget(self.row1b)
        self.add_widget(self.token)

        self.paste_token = Button(text='粘贴代码', size_hint_y=10, font_name=font)
        self.peer = TextInput(font_name=font)
        self.paste_token.bind(on_press=paste(self.peer))
        self.add_widget(self.paste_token)
        self.peer.bind(text=calculate)
        self.add_widget(self.peer)

        self.copy_password = Button(
            text='复制密钥', size_hint_y=10, font_name=font)
        self.key = TextInput(readonly=True, font_name=font)
        self.copy_password.bind(on_press=copy(self.key))
        self.add_widget(self.copy_password)
        self.add_widget(self.key)
        generate()


class AES128Crypt(GridLayout):
    def __init__(self, **kwargs):
        super(AES128Crypt, self).__init__(**kwargs)
        self.cols = 2
        self.row2b = GridLayout(cols=1, size_hint_x=100, size_hint_y=30)
        self.last_operation = None

        def encrypt(instance):
            try:
                if self.origin.text:
                    self.result.text = aes128_encrypt(
                        self.password.text, self.origin.text)
                    self.last_operation = 'encrypt'
            except ValueError:
                self.result.text = ''

        def decrypt(instance):
            try:
                if self.origin.text:
                    self.result.text = aes128_decrypt(
                        self.password.text, self.origin.text)
                    self.last_operation = 'decrypt'
            except InvalidToken:
                self.result.text = ''

        def auto_update(instance, value):
            if self.last_operation == 'encrypt':
                encrypt(instance)
            elif self.last_operation == 'decrypt':
                decrypt(instance)

        self.paste_password = Button(
            text='粘贴密码', size_hint_y=10, font_name=font)
        self.password = TextInput(size_hint_x=300, font_name=font)
        self.paste_password.bind(on_press=paste(self.password))
        self.add_widget(self.paste_password)
        self.add_widget(self.password)

        self.paste_origin = Button(text='粘贴文字', font_name=font)
        self.origin = TextInput(font_name=font)
        self.paste_origin.bind(on_press=paste(self.origin))
        self.row2b.add_widget(self.paste_origin)
        self.encrypt = Button(text='加密', font_name=font)
        self.encrypt.bind(on_press=encrypt)
        self.row2b.add_widget(self.encrypt)
        self.decrypt = Button(text='解密', font_name=font)
        self.decrypt.bind(on_press=decrypt)
        self.row2b.add_widget(self.decrypt)
        self.add_widget(self.row2b)
        self.origin.bind(text=auto_update)
        self.add_widget(self.origin)

        self.copy_result = Button(text='复制', size_hint_y=30, font_name=font)
        self.result = TextInput(readonly=True, font_name=font)
        self.copy_result.bind(on_press=copy(self.result))
        self.add_widget(self.copy_result)
        self.add_widget(self.result)


class Base64EncodeDecode(GridLayout):
    def __init__(self, **kwargs):
        super(Base64EncodeDecode, self).__init__(**kwargs)
        self.cols = 2
        self.row1b = GridLayout(cols=1, size_hint_x=50, size_hint_y=30)
        self.last_operation = None

        def encode(instance):
            self.result.text = base64_encode(self.origin.text)
            self.last_operation = 'encode'

        def decode(instance):
            if self.origin.text:
                try:
                    self.result.text = base64_decode(self.origin.text)
                    self.last_operation = 'decode'
                except binascii.Error:
                    self.result.text = ''
                except UnicodeDecodeError:
                    self.result.text = ''

        def auto_update(instance, value):
            if self.last_operation == 'encode':
                encode(instance)
            elif self.last_operation == 'decode':
                decode(instance)

        self.paste_origin = Button(text='粘贴', font_name=font)
        self.origin = TextInput(size_hint_x=300, font_name=font)
        self.paste_origin.bind(on_press=paste(self.origin))
        self.row1b.add_widget(self.paste_origin)
        self.encode = Button(text='编码', font_name=font)
        self.encode.bind(on_press=encode)
        self.row1b.add_widget(self.encode)
        self.decode = Button(text='解码', font_name=font)
        self.decode.bind(on_press=decode)
        self.row1b.add_widget(self.decode)
        self.add_widget(self.row1b)
        self.origin.bind(text=auto_update)
        self.add_widget(self.origin)

        self.copy_result = Button(text='复制', size_hint_y=30, font_name=font)
        self.result = TextInput(readonly=True, font_name=font)
        self.copy_result.bind(on_press=copy(self.result))
        self.add_widget(self.copy_result)
        self.add_widget(self.result)


class MainScreen(GridLayout):
    def __init__(self, **kwargs):
        super(MainScreen, self).__init__(**kwargs)
        self.cols = 1
        sm = ScreenManager(size_hint_y=100)

        def callback(title):
            def on_click(instance):
                sm.current = title
            return on_click

        def add_button(title):
            button = Button(text=title, size_hint_y=8, font_name=font)
            button.bind(on_press=callback(title))
            self.add_widget(button)

        add_button('X25519密钥交换')
        add_button('AES128信息加解密')
        add_button('Base64信息编解码')
        screen1 = Screen(name='X25519密钥交换')
        screen1.add_widget(X25519KeyExchange())
        screen2 = Screen(name='AES128信息加解密')
        screen2.add_widget(AES128Crypt())
        screen3 = Screen(name='Base64信息编解码')
        screen3.add_widget(Base64EncodeDecode())
        sm.add_widget(screen1)
        sm.add_widget(screen2)
        sm.add_widget(screen3)
        self.add_widget(sm)


class SimCryptApp(App):
    def build(self):
        return MainScreen()


if __name__ == "__main__":
    resource_add_path(get_resource_path())
    SimCryptApp().run()
