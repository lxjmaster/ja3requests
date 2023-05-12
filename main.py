from ja3requests.sessions import Session

with Session() as session:
    response = session.get("http://www.baidu.com")
    print(response)
    print(response.status_code)
    print(response.content)
