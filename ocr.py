import requests
from dotenv import load_dotenv
import os

load_dotenv()
def ocr_image(file_path):
    url = "https://api.ocr.space/parse/image"
    
    with open(file_path, 'rb') as f:
        response = requests.post(
            url,
            files={"file": f},
            data={
                "apikey": f"{os.getenv("OCR_KEY")}",
                
            }
        )

    result = response.json()
    return result['ParsedResults'][0]['ParsedText']
