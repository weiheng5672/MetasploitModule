# Metasploit Module: A Ruby example
```ruby
require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Hello World',
      'Description'    => %q{
        This module simply prints "Hello".
      },
      'Author'         => [ 'WeiHeng' ],
      'License'        => MSF_LICENSE
    ))
  end

  def run
    print_line("Hello")
  end
end
```
- 這段代碼是一個用於 Metasploit 模組開發的 "Hello World" 範例。
- 它展示了如何編寫一個最簡單的 Metasploit 模組，用來熟悉 Metasploit 模組的基本結構和工作流程。

## 引入核心庫：
```ruby
require 'msf/core'
```
- 這行代碼引入 Metasploit 框架的核心庫，使得模組能夠使用 Metasploit 提供的 API 和功能。

## 定義模組類：
```ruby
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
```
- 定義了一個 MetasploitModule 類，該類繼承(<) Msf::Auxiliary 
- 引入(include) Msf::Exploit::Remote::Tcp
- 創建一個輔助模組，利用 Metasploit 提供的功能來進行遠程 TCP 通信，實現網路掃描或信息收集等功能。

## 初始化模組：
```ruby
  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Hello World',
      'Description'    => %q{
        This module simply prints "Hello".
      },
      'Author'         => [ 'WeiHeng' ],
      'License'        => MSF_LICENSE
    ))
  end
```
- 在 initialize 方法中，設置了模組的基本信息，包括名稱、描述、作者和許可證。
- 這些信息會在 Metasploit 框架中顯示，幫助使用者理解模組的用途。
- 這段代碼是用來更新和初始化 Metasploit 模組的元數據（metadata）。
- 這些元數據包括模組的名稱、描述、作者和許可證等信息。
- update_info 是 Metasploit 框架中的一個方法，用來將這些信息更新到模組中。

具體來說：
### update_info
- update_info 是 Metasploit 框架中的一個內建方法，用來在模組中設置或更新元數據。
- 它通常在 initialize方法中使用，以便在模組初始化時將關鍵的模組信息添加到框架中。
### 參數 info
- info 是一個哈希 (Hash) 物件，它來自父類或框架中的預設信息，通常包含一些模組的基本元數據。可以在初始化過程中更新它。
### update_info(info, ...) 的作用
- update_info 方法的目的是將傳入的 info 哈希與你自定義的元數據（鍵值對）合併。
- 最終 info 將包含所有關於該模組的重要信息，包括你自己定義的 Name、Description 等，以及其他預設的或者繼承自父類的屬性。
### 元數據
update_info 內的 Hash 定義了模組的元數據，包括：
- 'Name'：模組的名稱。在這裡是 'Hello World'，這是模組的名稱，用來標識該模組。
- 'Description'：模組的描述。使用 %q{} 定義了一個多行字符串，描述了模組的功能。在這裡，描述的是「This module simply prints 'Hello'.」，表明模組的用途是打印 "Hello"。
- 'Author'：模組的作者。這裡列出了一個作者 'WeiHeng'，可以是多個作者，因此用了一個數組來表示。
- 'License'：許可證。這裡使用了 MSF_LICENSE，這是 Metasploit 框架的默認許可證。

### 作用
- 這段代碼的作用是告訴 Metasploit 框架該模組的基本信息。
- 當你在 Metasploit 控制台中使用 info 指令時，Metasploit 會顯示這些元數據來幫助用戶了解模組的功能和屬性。
## 實現 run 方法：
```ruby
  def run
    print_line("Hello")
  end
```
- run 方法是模組的核心部分，當你運行模組時，Metasploit 會調用這個方法。
- 在這個簡單的範例中，run 方法僅僅是打印 "Hello" 到控制台。

# 在Metasploit Console導入使用者自定義模組
## 檢查文件位置
- User module 預設放在 ~/.msf4/modules/ 目錄底下
- 確保模組文件放置在正確的目錄中。
- 對於用戶自定義模組，應該放在 ~/.msf4/modules/ 目錄下的適當子目錄中。
- 例如，如果是輔助模組，應放在 ~/.msf4/modules/auxiliary/。
## 重新加載 Metasploit
- 有時候 Metasploit 需要重新加載所有模組才能識別新添加的模組。
- 在Metasploit Console中使用以下命令重新加載所有模組：
```
msf> reload_all
```
## 測試模組
- 使用 search 命令來查找模組，然後使用 use 命令來嘗試加載它。
```
msf> search hello
```
- 查找結果
```
Matching Modules
================

   #   Name                                               Disclosure Date  Rank       Check  Description
   -   ----                                               ---------------  ----       -----  -----------
   0   exploit/multi/http/jira_plugin_upload              2018-02-22       excellent  Yes    Atlassian Jira Authenticated Upload Code Execution
   1   exploit/multi/http/baldr_upload_exec               2018-12-19       excellent  Yes    Baldr Botnet Panel Shell Upload Exploit
   2     \_ target: Auto                                  .                .          .      .
   3     \_ target: <= v2.0                               .                .          .      .
   4     \_ target: v2.2                                  .                .          .      .
   5     \_ target: v3.0 & v3.1                           .                .          .      .
   6   auxiliary/scanner/etcd/open_key_scanner            2018-03-16       normal     No     Etcd Keys API Information Gathering
   7   auxiliary/scanner/etcd/version                     2018-03-16       normal     No     Etcd Version Scanner
   8   auxiliary/scanner/kademlia/server_info             .                normal     No     Gather Kademlia Server Information
   9     \_ action: BOOTSTRAP                             .                .          .      Use a Kademlia2 BOOTSTRAP
   10    \_ action: PING                                  .                .          .      Use a Kademlia2 PING
   11  auxiliary/hello                                    .                normal     No     Hello World
   12  exploit/multi/browser/java_jre17_jaxws             2012-10-16       excellent  No     Java Applet JAX-WS Remote Code Execution
   13    \_ target: Generic (Java Payload)                .                .          .      .
   14    \_ target: Windows Universal                     .                .          .      .
   15    \_ target: Linux x86                             .                .          .      .
   16  auxiliary/dos/windows/games/kaillera               2011-07-02       normal     No     Kaillera 0.86 Server Denial of Service
   17  exploit/linux/http/kaltura_unserialize_cookie_rce  2017-09-12       excellent  Yes    Kaltura Remote PHP Code Execution over Cookie
   18  exploit/windows/mssql/ms02_056_hello               2002-08-05       good       Yes    MS02-056 Microsoft SQL Server Hello Overflow
   19  auxiliary/scanner/scada/modbus_banner_grabbing     .                normal     No     Modbus Banner Grabbing
   20  exploit/linux/mysql/mysql_yassl_hello              2008-01-04       good       No     MySQL yaSSL SSL Hello Message Buffer Overflow
   21  exploit/windows/mysql/mysql_yassl_hello            2008-01-04       average    No     MySQL yaSSL SSL Hello Message Buffer Overflow
   22    \_ target: MySQL 5.0.45-community-nt             .                .          .      .
   23    \_ target: MySQL 5.1.22-rc-community             .                .          .      .
   24  auxiliary/dos/ssl/dtls_changecipherspec            2000-04-26       normal     No     OpenSSL DTLS ChangeCipherSpec Remote DoS
   25  auxiliary/dos/ssl/dtls_fragment_overflow           2014-06-05       normal     No     OpenSSL DTLS Fragment Buffer Overflow DoS
   26  exploit/windows/local/unquoted_service_path        2001-10-25       great      Yes    Windows Unquoted Service Path Privilege Escalation

```
- 可以看到，第11個就是自己寫的模組，使用 use 命令去使用它
```
msf6 > use 11
```
- 以下就是進入模組的樣子
```
msf6 auxiliary(hello) >
```
- 查看一下 info 
```
msf6 auxiliary(hello) > info
```
- 查看結果
```

       Name: Hello World
     Module: auxiliary/hello
    License: Metasploit Framework License (BSD)
       Rank: Normal

Provided by:
  WeiHeng

Check supported:
  No

Basic options:
  Name    Current Setting  Required  Description
  ----    ---------------  --------  -----------
  RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
  RPORT                    yes       The target port (TCP)

Description:
  This module simply prints "Hello".

```
## 模組的詳細信息
- 當使用 info 指令查看模組信息時，Metasploit 框架會顯示模組的詳細信息。
- 這些信息來自於模組代碼中的 update_info 方法和 Metasploit 的默認行為。
- 模組排名:默認設置為 Normal，這表示模組的風險和使用優先級。
```
Rank: Normal
```
- 檢查支持:如果模組不支持任何檢查或不需要檢查，這會顯示為 No。
```
Check supported:
  No
```
### 基本選項:
```
Basic options:
  Name    Current Setting  Required  Description
  ----    ---------------  --------  -----------
  RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
  RPORT                    yes       The target port (TCP)

```
- RHOSTS 和 RPORT 是 Metasploit 自動生成的基本選項，這些是沒有在模組中明確指定的。
- 即使模組只是打印一行文字，Metasploit 仍然會顯示這些選項。
- 因為 Msf::Auxiliary 類別會自動包含這些基本選項。
## 使用模組
- 輸入show options指令查看需要輸入什麼選項
```
msf6 auxiliary(hello) > show options
```
- 查看結果
```
Module options (auxiliary/hello):                                                                                                                             
                                                                                                                                                              
   Name    Current Setting  Required  Description                                                                                                             
   ----    ---------------  --------  -----------                                                                                                             
   RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html                  
   RPORT                    yes       The target port (TCP)                                                                                                   
```
- 設定 RHOSTS ，隨便設一個IP
```
msf6 auxiliary(hello) > set RHOSTS 172.30.1.21
```
- 返回設定結果
```
RHOSTS => 172.30.1.21
```
- 設定 RPORT ，隨便設一個端口
```
msf6 auxiliary(hello) > set RPORT 80
```
- 返回設定結果
```
RPORT => 80
```
- 執行模組
```
msf6 auxiliary(hello) > run
```
* 執行結果
```
[*] Running module against 172.30.1.21

Hello
[*] Auxiliary module execution completed
```

