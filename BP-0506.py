from selenium import webdriver
import time as t
import requests
from tkinter import messagebox
from bs4 import BeautifulSoup

apikey = '87ecfa8f51fb640667f021ea964dfd5fbdec6713e3f74e90227952a391dfd1df'


def urlResultv1(cPage):
    global result
    global apikey

    vT = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': apikey, 'resource': cPage}
    reQ = requests.get(vT, params=params)
    
    if reQ.status_code > 199 and reQ.status_code < 300:
        if reQ.status_code == 204:
            return
        result = reQ.json()

    else: 
        print("유효하지 않은 상태 코드 " + str(reQ.status_code) + " v1")


def urlResultv2(cPage):
    global result
    global atag
    global apikey
    global maLi

    maLi = []
    cPage = requests.get(cPage)
    soup = BeautifulSoup(cPage.text, 'html.parser')

    atag = soup.findAll('a')

    if len(atag) == 0:
            print("링크가 없음")
            return

    
    for href in atag:
        link = href.get('href')
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': apikey, 'resource': link}
        reQ = requests.get(url, params=params)

        if reQ.status_code > 199 and reQ.status_code < 300:
            if reQ.status_code == 204:
                return
            
            result = reQ.json()
            print(result['response_code'])
            
            c = 0
            while result['response_code'] != 1:
                print("response_code : " + str(result['response_code']))
                print("재시도 중..")
                t.sleep(3)
                reQ = requests.get(url, params=params)
                result = reQ.json()
                if c > 3:
                    break
                c += 1


            if result['response_code'] == 1:
                if result['positives'] > 0:
                    maLi.append(href.text)
            
            else: return

        else: print("유효하지 않은 상태 코드 " + str(reQ.status_code) + " v2")
        
    
                            


try:
    driver = webdriver.Chrome('chromedriver.exe')

        # 브라우저 오픈!
    driver.get('https://www.google.com')


    # 메인

    pvOv = []

    while True:

        cPage = driver.current_url

        if cPage not in pvOv:

            pvOv.append(cPage)

            urlResultv1(cPage)
            
            while result['response_code'] != 1:
                t.sleep(3)
                print(result['response_code'])
                print("재시도 중..")
                urlResultv1(cPage)

            
            if result['response_code'] == 1:
                if result['positives'] > 0:
                    messagebox.showwarning("BP Warning", cPage + " 는 위험합니다. (현재페이지검사)")
                else:
                    messagebox.showwarning("BP Warning", cPage + " 는 안전합니다. (현재페이지검사)")

            else : pass


            urlResultv2(cPage)

            if len(maLi) > 0:
                maLi = ' '.join(maLi)

                messagebox.showwarning("BP Warning", maLi + " 은(는) 위험합니다. (악성링크탐지)")

            else :
                messagebox.showwarning("BP Warning", "악성 링크가 감지되지 않았습니다. (악성링크탐지)")


        # 중복 주소 방지
        elif cPage in pvOv:
            t.sleep(8)
            print("Overlap Prevention..")

except:
    messagebox.showwarning("BP Warning", "알 수 없는 오류")
            

    