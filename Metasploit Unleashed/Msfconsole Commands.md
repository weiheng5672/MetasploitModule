

# search

- 如果你對目標模組有大致的了解（例如漏洞代碼、名稱或相關描述），可以使用 `search` 命令來定位它。

- 搜索功能會在以下位置查找匹配的字串：

    - 模組名稱（Module Names）
    - 模組描述（Descriptions）
    - 參考文獻（References）
    - 其他相關元數據（Metadata）
    
    這樣的設計可以幫助用戶快速找到與目標漏洞相關的模組。

```
msf6 > search blue
```



# use

- 當你決定使用某個特定的模組時，需要使用 `use` 命令來選擇該模組。這個命令會讓你進入該模組。

```
msf > use 模組名稱或搜尋結果的序號
```

# show options

首先，可以使用 show options 命令查看當前模組的選項和參數
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
```

# set

- `set` 命令用於配置你正在使用的當前模組的選項和參數。這些選項是模組運行所需的配置，例如目標地址、端口號、用戶名等。

- 當你選擇了一個模組（例如漏洞利用模組或輔助模組），該模組通常需要一些參數來指定如何與目標交互。`set` 命令用來設置這些參數。

# run

- `run` 命令用於執行配置完的模組

```
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
```

# back

- 當完成使用某個模組，或不小心選擇錯誤的模組，可以使用 `back` 命令來退出當前模組。

```
msf exploit(windows/smb/ms17_010_eternalblue) > back
msf >
```


