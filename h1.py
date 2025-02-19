import time
import argparse
import re
import json
from datetime import datetime, timedelta
from selenium.webdriver import Chrome, ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait

hacktivity_url = 'https://hackerone.com/hacktivity/overview'
page_loading_timeout = 10

def parse_time(time_str):
    match = re.search(r"Disclosed\s+(\d+)\s*(hr|hrs|hour|hours|min|mins|minute|minutes|day|days)\s+ago", 
                  time_str, re.IGNORECASE)
    if match:
        value = int(match.group(1))
        unit = match.group(2).lower()
    
        if unit in ['hr', 'hrs', 'hour', 'hours']:
            disclosed_time = datetime.now() - timedelta(hours=value)
        elif unit in ['min', 'mins', 'minute', 'minutes']:
            disclosed_time = datetime.now() - timedelta(minutes=value)
        elif unit in ['day', 'days']:
            disclosed_time = datetime.now() - timedelta(days=value)
        else:
            disclosed_time = datetime.now()

    formatted_time = disclosed_time.strftime("%Y-%m-%d %H:%M:%S")
    return formatted_time
        
def extract_reports(cards):
    reports = []
    for card in cards:
        report = {
            'program': '',
            'title': '',
            'link': '',
            'time': '',
            'summary': '',
            'severity': ''
        }

        try:
            # (1) 提取项目名称：位于data-testid="hacktivity-item"内的.truncate中的span
            program = card.find_element(By.CSS_SELECTOR, "div[data-testid='hacktivity-item'] .truncate span").text
            report['program'] = program
        except Exception as e:
            print(f'项目名称提取失败: {e}')
            pass

        try:
            # (2) 提取报告标题：位于data-testid="report-title"内的span.line-clamp-2中
            title = card.find_element(By.CSS_SELECTOR, "div[data-testid='report-title'] span.line-clamp-2").text
            report['title'] = title
        except Exception as e:
            print(f'报告标题提取失败: {e}')
            pass

        try:
            # (3) 提取报告详情链接：位于data-testid="report-title"内的a.routerlink
            link = card.find_element(By.CSS_SELECTOR, "a.routerlink").get_attribute("href")
            report['link'] = link
        except Exception as e:
            print(f'报告链接提取失败: {e}')
            pass

        try:
            # (4) 提取披露时间：位于data-testid="report-disclosed-at"内
            disclosed = card.find_element(By.CSS_SELECTOR, "div[data-testid='report-disclosed-at'] span[title]").get_attribute("title")
            report['time'] = disclosed
        except Exception as e:
            print(f'披露时间提取失败: {e}')
            pass

        try:
            # (5) 提取报告摘要：位于interactive_markdown内部的div.interactive_markdown__p
            summary = card.find_element(By.CSS_SELECTOR, "div.interactive_markdown__p").text
            report['summary'] = summary
        except Exception as e:
            print(f'报告摘要提取失败: {e}')
            pass

        try:
            # (6) 提取严重性：位于data-testid="report-severity"下的span
            severity = card.find_element(By.XPATH, "//*[@data-testid='report-severity']//span[not(child::*)]").text
            report['severity'] = severity
        except Exception as e:
            print(f'严重性提取失败: {e}')
            pass
        
        if report['link'] == '':
            continue
        
        reports.append(report)

    return reports

def fetch(page_count):
    options = ChromeOptions()
    options.add_argument('no-sandbox')
    options.add_argument('headless')
    driver = Chrome(options=options)

    new_reports = []
    try:
        driver.get(hacktivity_url)
        # 等待页面加载完成
        WebDriverWait(driver, 10).until(lambda d: d.execute_script("return document.readyState") == "complete")
        time.sleep(page_loading_timeout)

        page = 0
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        next_page_button = driver.find_element(By.CSS_SELECTOR, 'button[data-testid=\'hacktivity-next-button\']')
        while True:
            cards = driver.find_elements(By.CSS_SELECTOR, "div.card")
            parsed_reports = extract_reports(cards)
            #print('======================================')
            #print(parsed_reports)
            new_reports += parsed_reports

            page += 1
            print('已处理页面:', page)
            if page >= page_count:
                break

            time.sleep(5)
            driver.execute_script("arguments[0].click();", next_page_button)
            time.sleep(page_loading_timeout)
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
    except Exception as e:
        print(e)
        now = datetime.now().strftime('%Y-%m-%d')
        driver.get_screenshot_as_file('error-%s.png' % now)
    finally:
        driver.close()

    return new_reports


if __name__ == '__main__':
    argparser = argparse.ArgumentParser()
    argparser.add_argument('-c', '--count', type=int, help='set fetch page count', default='1')
    args = argparser.parse_args()
    new_reports = fetch(args.count)
    print(f'共获取到 {len(new_reports)} 条新报告')
    with open('new_reports.json', 'w') as f:
        json.dump(new_reports, f, indent=4)
