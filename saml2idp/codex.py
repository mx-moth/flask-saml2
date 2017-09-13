# Portions borrowed from:
# http://stackoverflow.com/questions/1089662/python-inflate-and-deflate-implementations
import zlib
import base64


def decode_base64_and_inflate(b64string):
    if type(b64string) is bytes:
        b64string = b64string.decode('utf-8')
    decoded_data = base64.b64decode(b64string)
    return zlib.decompress(decoded_data, -15)


def deflate_and_base64_encode(string_val):
    zlibbed_str = zlib.compress(string_val.encode('utf-8'))
    compressed_string = zlibbed_str[2:-4]
    return base64.b64encode(compressed_string)


def nice64(src):
    """ Returns src base64-encoded and formatted nicely for our XML. """
    if type(src) == str:
        src = src.encode('utf-8')
    return base64.b64encode(src)
