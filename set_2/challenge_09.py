from utils.MyAES import pkcs_7_custom_pad


def main():
    text = "YELLOW SUBMARINE"
    text_bytes = bytes(text, encoding="utf-8")
    print(pkcs_7_custom_pad(text_bytes, 20))

if __name__ == '__main__':
    main()