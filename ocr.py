import requests
def ocr_image(file_path):
    url = "https://api.ocr.space/parse/image"
    
    with open(file_path, 'rb') as f:
        response = requests.post(
            url,
            files={"file": f},
            data={
                "apikey": "<ENTER YOUR API KEY HERE THAT YOU RECIEVED IN YOUR EMAIL>",
                
            }
        )

    result = response.json()
    return result['ParsedResults'][0]['ParsedText']