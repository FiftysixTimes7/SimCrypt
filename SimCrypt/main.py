import binascii
import os
import sys

from cryptography.fernet import InvalidToken
from kivy.app import App
from kivy.resources import resource_add_path
from kivy.uix.button import Button
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.screenmanager import Screen, ScreenManager
from kivy.uix.textinput import TextInput

from backend import (aes128_decrypt, aes128_encrypt, base64_decode,
                     base64_encode, x25519_key_derive, x25519_key_gen)

font = 'SourceHanSansCN-Regular.ttf'


def get_resource_path():
    '''Returns path containing content - either locally or in pyinstaller tmp file. Fix for one-file generation.'''
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS)

    return os.path.join(os.path.abspath("."))


class X25519KeyExchange(GridLayout):
    def __init__(self, **kwargs):
        super(X25519KeyExchange, self).__init__(**kwargs)
        self.cols = 2
        private, public = x25519_key_gen()
        self.add_widget(Label(text='你的交换代码', size_hint_x=50, font_name=font))
        self.add_widget(
            TextInput(readonly=True, text=public.strip(), size_hint_x=300, font_name=font))
        self.add_widget(Label(text='对方的交换代码', size_hint_x=50, font_name=font))
        self.peer = TextInput(size_hint_x=300, font_name=font)

        def calculate(instance, value):
            if value:
                try:
                    key = x25519_key_derive(private, value)
                    self.key.text = key.hex()
                except ValueError:
                    pass

        self.peer.bind(text=calculate)
        self.add_widget(self.peer)
        self.add_widget(Label(text='相同的密钥', size_hint_x=50, font_name=font))
        self.key = TextInput(readonly=True, size_hint_x=300, font_name=font)
        self.add_widget(self.key)


class AES128Encrypt(GridLayout):
    def __init__(self, **kwargs):
        super(AES128Encrypt, self).__init__(**kwargs)
        self.cols = 2
        self.add_widget(Label(text='密码', size_hint_x=50, font_name=font))
        self.password = TextInput(size_hint_x=300, font_name=font)
        self.add_widget(self.password)
        self.add_widget(Label(text='明文', size_hint_x=50, font_name=font))
        self.data = TextInput(size_hint_x=300, font_name=font)

        def calculate(instance, value):
            if value:
                try:
                    token = aes128_encrypt(
                        self.password.text, self.data.text)
                    self.token.text = token
                except ValueError:
                    self.token.text = ''

        self.data.bind(text=calculate)
        self.add_widget(self.data)
        self.add_widget(Label(text='密文', size_hint_x=50, font_name=font))
        self.token = TextInput(readonly=True, size_hint_x=300, font_name=font)
        self.add_widget(self.token)


class AES128Decrypt(GridLayout):
    def __init__(self, **kwargs):
        super(AES128Decrypt, self).__init__(**kwargs)
        self.cols = 2
        self.add_widget(Label(text='密码', size_hint_x=50, font_name=font))
        self.password = TextInput(size_hint_x=300, font_name=font)
        self.add_widget(self.password)
        self.add_widget(Label(text='密文', size_hint_x=50, font_name=font))
        self.token = TextInput(size_hint_x=300, font_name=font)

        def calculate(instance, value):
            if value:
                try:
                    data = aes128_decrypt(
                        self.password.text, self.token.text)
                    self.data.text = data
                except InvalidToken:
                    self.data.text = ''

        self.token.bind(text=calculate)
        self.add_widget(self.token)
        self.add_widget(Label(text='明文', size_hint_x=50, font_name=font))
        self.data = TextInput(readonly=True, size_hint_x=300, font_name=font)
        self.add_widget(self.data)


class Base64Encode(GridLayout):
    def __init__(self, **kwargs):
        super(Base64Encode, self).__init__(**kwargs)
        self.cols = 2
        self.add_widget(Label(text='未编码', size_hint_x=50, font_name=font))
        self.origin = TextInput(size_hint_x=300, font_name=font)

        def calculate(instance, value):
            encoded = base64_encode(self.origin.text)
            self.encoded.text = encoded.strip()

        self.origin.bind(text=calculate)
        self.add_widget(self.origin)
        self.add_widget(Label(text='已编码', size_hint_x=50, font_name=font))
        self.encoded = TextInput(
            readonly=True, size_hint_x=300, font_name=font)
        self.add_widget(self.encoded)


class Base64Decode(GridLayout):
    def __init__(self, **kwargs):
        super(Base64Decode, self).__init__(**kwargs)
        self.cols = 2
        self.add_widget(Label(text='已编码', size_hint_x=50, font_name=font))
        self.origin = TextInput(size_hint_x=300, font_name=font)

        def calculate(instance, value):
            if value:
                try:
                    decoded = base64_decode(self.origin.text)
                    self.decoded.text = decoded
                except binascii.Error:
                    self.decoded.text = ''
                except UnicodeDecodeError:
                    self.decoded.text = ''

        self.origin.bind(text=calculate)
        self.add_widget(self.origin)
        self.add_widget(Label(text='未编码', size_hint_x=50, font_name=font))
        self.decoded = TextInput(
            readonly=True, size_hint_x=300, font_name=font)
        self.add_widget(self.decoded)


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
            button = Button(text=title, size_hint_y=10, font_name=font)
            button.bind(on_press=callback(title))
            self.add_widget(button)

        add_button('X25519密钥交换')
        add_button('AES128信息加密')
        add_button('AES128信息解密')
        add_button('Base64信息编码')
        add_button('Base64信息解码')
        screen1 = Screen(name='X25519密钥交换')
        screen1.add_widget(X25519KeyExchange())
        screen2 = Screen(name='AES128信息加密')
        screen2.add_widget(AES128Encrypt())
        screen3 = Screen(name='AES128信息解密')
        screen3.add_widget(AES128Decrypt())
        screen4 = Screen(name='Base64信息编码')
        screen4.add_widget(Base64Encode())
        screen5 = Screen(name='Base64信息解码')
        screen5.add_widget(Base64Decode())
        sm.add_widget(screen1)
        sm.add_widget(screen2)
        sm.add_widget(screen3)
        sm.add_widget(screen4)
        sm.add_widget(screen5)
        self.add_widget(sm)


class SimCryptApp(App):
    def build(self):
        return MainScreen()


if __name__ == "__main__":
    resource_add_path(get_resource_path())
    SimCryptApp().run()
