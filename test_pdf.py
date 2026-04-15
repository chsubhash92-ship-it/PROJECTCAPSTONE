import requests

try:
    print("Analyzing CSV...")
    res1 = requests.post('http://127.0.0.1:14094/api/analyze_csv', files={'file': open('test.csv', 'rb')})
    if res1.status_code != 200:
        print("Analysis failed:", res1.text)
        exit(1)
        
    data = res1.json()
    print("Generating PDF...")
    res2 = requests.post('http://127.0.0.1:14094/api/download_pdf', json=data)
    print(f"Status: {res2.status_code}")
    if res2.status_code != 200:
        print(res2.text[:500])
    else:
        print("Success, PDF length:", len(res2.content))
except Exception as e:
    print(f"Exception: {e}")
