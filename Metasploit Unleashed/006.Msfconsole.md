# What is the MSFconsole?

MSFconsole 是 Metasploit Framework（MSF）最受歡迎的介面之一。它提供了一個集中式的控制台，使你能高效地訪問 MSF 中幾乎所有的選項。對於初學者來說，MSFconsole 可能會顯得有些令人生畏，但一旦你學會了指令的語法，你會開始欣賞使用這個介面的強大功能。

簡而言之，MSFconsole 是 Metasploit 的核心介面之一，它讓使用者能夠直接操作和管理 Metasploit 的各種模組、攻擊選項、目標設定等，對於進行滲透測試和漏洞利用非常有幫助。


# Benefits to Using MSFconsole

## It is the only supported way to access most of the features within Metasploit.

MSFconsole 是唯一官方支持用來訪問 Metasploit 中大部分功能的方式。許多 Metasploit 的核心模組和指令都只能通過 MSFconsole 來使用，它提供了完整的功能和指令集，其他介面可能無法完全支持所有功能。這使得 MSFconsole 成為學習和使用 Metasploit 時最穩定和可靠的選擇。

## Provides a console-based interface to the framework

MSFconsole 提供了一個基於命令行的介面，這意味著使用者可以直接與 Metasploit 框架進行互動，而不需要依賴圖形界面。這樣的設計不僅讓操作更加靈活，還能提高處理大量命令時的效率，對於進行滲透測試和漏洞分析的專業人員來說，這種界面提供了極大的便利。

## Contains the most features and is the most stable MSF interface

MSFconsole 擁有最完整的功能集，並且是 Metasploit 框架中最穩定的介面。它包含了 Metasploit 所有的模組和選項，包括漏洞利用、後門建立、信息收集等。其他介面可能在某些情況下無法提供這麼多功能，因此 MSFconsole 是進行深入測試和利用的首選介面。

## Full readline support, tabbing, and command completion

MSFconsole 支援完整的 readline 功能，包括命令補全和自動縮排。這使得使用者在輸入命令時更加高效，可以通過按下 tab 鍵來自動補全命令，並且可以輕鬆查看和重用之前的命令。這不僅提高了操作的速度，也減少了輸入錯誤的機會，提升了使用體驗。

## Execution of external commands in msfconsole is possible

在 MSFconsole 中，你還可以執行外部命令，這讓你能夠將其他系統工具與 Metasploit 框架結合使用。例如，你可以在 Metasploit 中運行操作系統命令來收集更多的系統信息，或是進行其他操作，如檔案管理或網絡掃描。這種靈活性使得 MSFconsole 成為一個非常強大的工具，能夠應對多種情境。

```
msf > ping -c 1 192.168.1.100
[*] exec: ping -c 1 192.168.1.100

PING 192.168.1.100 (192.168.1.100) 56(84) bytes of data.
64 bytes from 192.168.1.100: icmp_seq=1 ttl=128 time=10.3 ms

--- 192.168.1.100 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 10.308/10.308/10.308/0.000 ms
msf >

```
- 這是一個在 MSFconsole 中執行外部命令的範例。

- 使用了 ping 命令來測試網絡連通性。

在這個範例中：
```
msf > ping -c 1 192.168.1.100 
```
是在 MSFconsole 中輸入的命令。

這個命令的作用是發送一個 ICMP ping 請求到 IP 地址 192.168.1.100，並顯示回應。

```
[ * ] exec: ping -c 1 192.168.1.100 
```
是 MSFconsole 執行該命令時的提示，表示正在執行外部命令 ping。

```
PING 192.168.1.100 (192.168.1.100) 56(84) bytes of data.
64 bytes from 192.168.1.100: icmp_seq=1 ttl=128 time=10.3 ms

--- 192.168.1.100 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 10.308/10.308/10.308/0.000 ms
```
是 ping 命令的輸出，顯示了該 IP 地址的網絡連通性，包括往返時間（RTT）和丟包情況。

這個功能允許你在不退出 MSFconsole 的情況下，使用外部命令進行額外的操作或信息收集，這是 MSFconsole 的一大優勢。


# Launching MSFconsole

- 啟動 MSFconsole 非常簡單，只需要在命令行中輸入 `msfconsole` 就能啟動它。

- 使用 `-q` 參數（選項）以安靜模式啟動 MSFconsole，會去掉啟動時顯示的標語，直接進入 MSFconsole 界面。


```
root@kali:# msfconsole -q
msf >
```
- MSFconsole 位於 Metasploit 框架的安裝目錄下，具體路徑是 `/usr/share/metasploit-framework/msfconsole`。

- 可以在命令行中將 `-h` 參數傳遞給 `msfconsole`，這樣它會顯示出可用的其他用法選項或幫助信息。

```
root@kali:# msfconsole -h
```

- 進入 MSFconsole 並處於命令提示符下時，可以輸入 help 或 ? 顯示可用命令的列表，以及每個命令的用途說明。
```
msf > help
```

# Tab Completion

- MSFconsole 旨在提供一個快速且高效的方式來操作 Metasploit 框架，尤其是在面對大量模組時。這種快速性不僅來自於命令執行本身，還來自於一些輔助功能，如 Tab 鍵自動補全。

- 在 Metasploit 存在大量模組，記住每個模組的具體名稱和路徑是不可能的，你只需要輸入已知的部分名稱，然後按 Tab 鍵，MSFconsole 就會提供一個模組名稱的建議或自動完成整個模組名稱。

- MSFconsole 的 Tab 完成功能依賴於 Ruby 的 readline 擴展庫。這是許多命令行工具中常見的功能庫，提供了自動補全、命令歷史記錄等功能。這意味著幾乎所有 MSFconsole 中的命令都支持 Tab 完成。

MSFconsole 提供的 Tab 鍵自動補全功能能夠讓用戶在操作過程中提高效率，特別是在面對大量命令和模組時，能夠減少記憶負擔並加速操作流程。