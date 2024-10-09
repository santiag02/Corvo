# Corvo

This is a tool that has as aim to use [intelX](https://intelx.io) leaks and correlate them to figure out the most proeminent threat actors, families and of course, the number of leaks based in domains.

As the first step you need send your IntelX API to do requests.
After that if you want uso some date filter you need pass a date of beggining and ending with arguments '-a' for after and '-b' for before.

The term to search at the moment we are working with domains, like "google.com", so we will search for urls (https://something.google.com) or users that use this domain (john_doe@google.com).

Other way is to create a file or use the example file to search domains:

```
[DOMAINS]
health = test1.com.br,test2.com.br
food =test3.com.cl, test4.com.cl
```

For get leaks compared with your domain you need download the files. 


```
$ python main.py -h
usage: main.py [-h] [-i] [-a AFTER] [-b BEFORE] [-p LEAK_PATH] -t TERM -f FILEPATH [-r] [-d]

A credential harvester, powered by the IntelX API.

options:
  -h, --help    show this help message and exit
  -i, --init    First step. Save your IntelX credentials
  -a AFTER      Date started to collecting infostealer leaks. Format: YYYY-MM-DD
  -b BEFORE     Date finished to collecting infostealer leaks. Format: YYYY-MM-DD
  -p LEAK_PATH  Pass a path of leaks only of infostealers to be parsed, if you already download it.
  -t TERM       The term (str) to be searched
  -f FILEPATH   A config file with domains.
  -r            Evade flow to reduce queries
  -d            More info for output, debugger
```

## Uses cases

### Search for a domain using dates (needs start and end) and activate the debugger

1. Pass the date range with arguments: -a, -b
2. Activate the debugger with the -d argument. Debugger mode will print on the screen the step-by-step verification process per file.
3. Pass the domain as term -t
4. The search result will be saved in the file corvo.leaks

```
$ python main.py -a 2024-09-01 -b 2024-09-30 -t test.com.br -d
Total citations [test.com.br]: 4
2024-09-16T06:46:25.887072Z::Passwords.txt=6f94d4a5-. . . 
{'company': [{'soft': 'Chrome Default (127.0.6533.122)', 'url': 'http://www.test.com.br/', 'username': 'john_doe@test.com.br', 'password': '1234567'}], 'client': []}
GroupName: None
2024-09-16T06:46:25.783095Z::AllPasswords.txt=2b51ac1c-. . . 
{'company': [{'soft': 'Chrome Default (127.0.6533.122)', 'url': 'http://www.test.com.br/', 'username': 'john_doe@test.com.br', 'password': '1234567'}], 'client': []}
GroupName: None
Checking the ComboListFresh.txt[Part1of2]::5d50672f-. . . tree
Find out the leaks file in the tree: AllPasswords.txt::26df3-. . .
2024-09-07T12:36:53.138062Z::AllPasswords.txt=26df3-. . .
Unknown pattern for file: 2fa96df3-. . .
{'company': [], 'client': []}
GroupName: None
Checking the Domain.txt[Part1of2]::0b9a0563-. . . tree
Find out the leaks file in the tree: AllPasswords.txt::2fa96df3-. . .
2024-09-07T12:36:52.897799Z::AllPasswords.txt=2fa96df3-. . .
Total group names: {'unknown': 3}
Check the result at corvo.leaks file
```

### Search for a domain using dates (needs start and end) and activate the debugger with reduced queries ('-r') enable

With '-r' enabled, only files that are 'Passwords' files will be readed and the code flow will not search for them in the tree file.

```
$ python main.py -a 2024-09-01 -b 2024-09-30 -t test.com.br -d -r
Total citations [test.com.br]: 4
2024-09-16T06:46:25.887072Z::Passwords.txt=6f94d4a5-. . . 
{'company': [{'soft': 'Chrome Default (127.0.6533.122)', 'url': 'http://www.ituranweb.com.br/', 'username': 'john_doe@test.com.br', 'password': '1234567'}], 'client': []}
GroupName: None
2024-09-16T06:46:25.783095Z::AllPasswords.txt=2b51ac1c-. . .
{'company': [{'soft': 'Chrome Default (127.0.6533.122)', 'url': 'http://www.ituranweb.com.br/', 'username': 'john_doe@test.com.br', 'password': '1234567'}], 'client': []}
GroupName: None
Total group names: {'unknown': 2}
Check the result at corvo.leaks file
```

## Output

All data output will be written directly to the file corvo.leaks, unless you have activated debugger mode with '-d', this will print it to the terminal step by step.

- The header in the search for a term comes at the time executed and the key in the search for a domain file.

```
#########################
## 2024-10-07_22-54-15 ##
#########################
Company Leaks (2) - test.com.br
{"soft": "Chrome Default (127.0.6533.122)", "url": "http://www.test.com.br/", "username": "john_doe@test.com.br", "password": "1234567"}
{"soft": "Chrome Default (127.0.6533.122)", "url": "https://test.com.br/", "username": "john_doe@test.com.br", "password": "123456"}

Client Leaks (0) - test.com.br


Total group names: {'unknown': 2}
```

## Workflow

|![](https://github.com/santiag02/Corvo/blob/main/media/corvo_workflow.png)|
|:---:|
|Corvo - Workflow|