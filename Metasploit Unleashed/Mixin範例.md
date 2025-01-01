```ruby
# 定義一個父類別 MyParent
class MyParent
  # 定義一個方法 woof，輸出 "woof!"
  def woof
    puts "woof!"  # 這是 MyParent 類的基礎功能，將被繼承。
  end
end

# 定義一個子類別 MyClass，繼承自 MyParent
class MyClass < MyParent
  # MyClass 繼承了 MyParent 的 woof 方法，並未改寫任何行為
end

# 建立 MyClass 的一個實例，並調用 woof 方法
object = MyClass.new
object.woof()  # 輸出 "woof!"，這裡展示了繼承機制的基本用法。

# 到這邊，都是一般的物件導向概念

# 定義一個模組 MyMixin
module MyMixin
  # 定義一個方法 woof，覆寫同名方法
  def woof
    puts "hijacked the woof method!"  # Mixin 提供新的行為，將覆寫繼承的 woof 方法。
  end
end

# 定義一個新的類別 MyBetterClass，繼承自 MyClass，並包含 MyMixin
class MyBetterClass < MyClass
  include MyMixin  # 使用 include 將 MyMixin 的功能注入到 MyBetterClass
end

# 建立 MyBetterClass 的一個實例，並調用 woof 方法
better_object = MyBetterClass.new
better_object.woof()  # 輸出 "hijacked the woof method!"，顯示 Mixin 覆寫了原本的 woof 方法。
```

---

### **該範例如何實踐 Mixin：**  
1. **模組定義新功能：**  
   `MyMixin` 定義了一個 `woof` 方法，這是一個可以用於覆寫類別行為的功能模組。  

2. **模組注入類別：**  
   使用 `include` 關鍵字，將 `MyMixin` 的功能注入到 `MyBetterClass` 中。這是一種實踐 Mixin 的方式，因為模組並未改變類別的繼承結構，而是作為附加功能被動態地注入。  

3. **覆寫方法：**  
   `MyMixin` 中的 `woof` 方法取代了 `MyClass` 從 `MyParent` 繼承的 `woof` 方法，這展示了 Mixin 能改變類別行為的能力。  

4. **多樣化功能：**  
   通過注入不同的模組，可以輕鬆為類別添加或改變行為，這是一種比多重繼承更靈活的設計方式，正是 Mixin 的核心理念。  

這段程式展示了如何用 Mixin 動態地改變類別行為，同時保持簡潔且不影響繼承結構。
