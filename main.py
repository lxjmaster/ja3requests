from ja3requests.sessions import Session


headers = {
    "connection": "keep-alive"
    # "Accept-Encoding": "deflate, br, gzip"
}
with Session() as session:
    # response = session.get("http://127.0.0.1:8080", headers=headers)
    response = session.get("http://www.baidu.com")
    # print(response.headers)
    # print(response)
    # print(response.status_code)
    # print(response.content)
    print(response.text)
    # with open("baidu.html", "w+") as f:
    #     f.write(response.text)


# import requests
#
# requests.get("http://127.0.0.1:8080", headers=headers)

# import socket
#
# # create a socket object
# client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#
# # connect to the server
# host = 'www.baidu.com'
# port = 80
# client_socket.connect((host, port))
#
# request = "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n".format(host)
# client_socket.send(request.encode())
#
# response = b''
# while True:
#     data = client_socket.recv(1024)
#     if not data:
#         break
#     response += data
#
# # decode the response headers
# response_headers = response.decode().split('\r\n')
#
# content_length = None
# transfer_encoding = None
#
# for header in response_headers:
#     if 'Content-Length' in header:
#         content_length = int(header.split(': ')[1])
#     elif 'Transfer-Encoding' in header:
#         transfer_encoding = header.split(': ')[1]
#
# print(content_length, transfer_encoding)
# if transfer_encoding == 'chunked':
#     response_body = b''
#     while True:
#         chunk_size = int(response[:response.find(b'\r\n')], 16)
#         if chunk_size == 0:
#             break
#         response = response[response.find(b'\r\n')+2:]
#         response_body += response[:chunk_size]
#         response = response[chunk_size+2:]
# else:
#     # read the response body using content length
#     response_body = client_socket.recv(content_length)
#
# print(response[len(response)-content_length:])
# client_socket.close()
