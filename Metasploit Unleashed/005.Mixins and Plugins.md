# A Quick Diversion into Ruby
## Every Class only has one parent

Ruby 的類別只能繼承自單一父類別，這種單繼承的設計提供了簡單且一致的結構

## A class may include many Modules

類別可以透過包含多個模組，來補足單繼承的不足。模組能加入額外的方法，甚至改寫原有的方法，使得類別具備更多功能。

## Modules can add new methods

模組可以定義新方法，並將其提供給包含該模組的類別，進而讓類別擴展功能而不影響繼承層級。

## Modules can overload old methods

模組可以改寫類別中已有的方法，透過這種方式，模組能夠調整類別的行為，實現更高的靈活性。

## Metasploit modules inherit Msf::Module and include mixins to add features.

- Msf::Module 是 Metasploit 框架中所有模組的基礎類別，提供了核心功能和行為。
- 所有的 Metasploit 模組（例如 Exploit、Auxiliary、Payload 等）都繼承自這個基類，以確保它們擁有一致的基本功能和結構。
- Mixin 是 Ruby 模組的一個特性，允許類別透過 include 或 prepend 加入模組的方法。
- Metasploit 框架中，大量的功能是透過 mixin 模組來提供的，而不是直接寫在基類中。這讓框架更加模組化、靈活可擴展。

# Metasploit Mixins
## Mixins are quite simply, the reason why Ruby rocks.
### Mixins include one class into another

Mixin 是 Ruby 的一大特色，允許將模組的功能注入到類別中，這使得類別可以在不改變繼承結構的情況下快速擴展功能，提高了程式的靈活性與可重用性。

### This is both different and similar to inheritance

Mixin 和繼承一樣可以共享和覆寫方法，但不同的是，Mixin 不會改變類別的繼承層級，讓程式可以避免多重繼承的複雜性，同時保持靈活性和簡潔性。

### Mixins can override a class’ methods

Mixin 可以覆寫類別的現有方法，這讓類別的行為變得可定制，能針對具體的需求進行功能增強，為模組的設計提供更多可能性。


## Mixins can add new features and allows modules to have different ‘flavors’.
### Protocol-specific (HTTP, SMB)

協定相關的 mixin，例如 HTTP 或 SMB，能為模組注入協定特定的功能，使模組可以快速實現與這些協定的交互，提升開發效率。

### Behaviour-specific (brute force)

行為導向的 mixin，例如暴力破解，為模組提供了一套既有的行為模式，開發人員可以直接利用這些模式，而無需從頭開始實現。

### connect() is implemented by the TCP mixin

TCP mixin 提供了一個通用的 connect() 方法，讓模組能快速建立 TCP 連線，這為需要網路交互的模組提供了基礎功能

### connect() is then overloaded by FTP, SMB, and others

其他協定（如 FTP 和 SMB）透過覆寫 connect() 方法，加入協定專屬的邏輯，這讓模組能針對不同的協定實現專屬行為。

## Mixins can change behavior.
### The Scanner mixin overloads run()

Scanner mixin 改寫了 run() 方法，將其拆分成更細緻的 run_host() 和 run_range()，以便處理不同層級的掃描需求。

### Scanner changes run() for run_host() and run_range()

透過將 run() 拆分為 run_host() 和 run_range()，Scanner mixin 能更有效率地管理多目標掃描操作，提升執行靈活性。

### It calls these in parallel based on the THREADS setting

Scanner mixin 根據 THREADS 的設定平行執行多個任務，充分利用多核心處理器的效能，加快掃描過程。

### The BruteForce mixin is similar

BruteForce mixin 的工作方式類似，透過平行化處理和覆寫方法來實現高效能的暴力破解，同時保持執行的靈活性與效率。


# Metasploit Plugins

## Plugins work directly with the API.
### They manipulate the framework as a whole

插件直接與 Metasploit 的 API 互動，能操作框架的核心功能，實現對整體框架的定制化控制，讓使用者能更靈活地管理和拓展 Metasploit 的功能。

### Plugins hook into the event subsystem

插件可以掛接到事件子系統中，監聽並處理框架內的各種事件，這讓它們能在特定情況下自動執行操作，從而實現即時響應

### They automate specific tasks that would be tedious to do manually

插件能自動化完成一些繁瑣的手動操作，比如批量生成會話或管理大量目標，極大地提高了工作效率，減少了人為操作的錯誤。

## Plugins only work in the msfconsole.
### Plugins can add new console commands

插件能為 msfconsole 添加自定義命令，這些命令可以擴展標準命令集，讓使用者更方便地完成特定任務或執行複雜操作。

### They extend the overall Framework functionality

插件通過增強或擴展框架的功能，使得 Metasploit 不僅限於內建的模組和工具，而是可以根據需求不斷升級和定制，滿足更廣泛的攻防場景需求。
