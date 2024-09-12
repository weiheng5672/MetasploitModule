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
- 使用 search 命令來查找你的模組，然後使用 use 命令來嘗試加載它。
```
msf> search hello
```
