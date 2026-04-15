import requests

try:
    res = requests.post('http://127.0.0.1:14094/api/analyze_csv', files={'file': open('test.csv', 'rb')})
    print(f"Status: {res.status_code}")
    print(res.text[:500])
except Exception as e:
    print(f"Exception: {e}")
