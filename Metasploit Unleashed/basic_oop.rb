# ruby basic_oop.rb

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
