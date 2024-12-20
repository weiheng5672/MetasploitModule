##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# This sample auxiliary module simply displays the selected action and
# registers a custom command that will show up when the module is used.
#
###
class MetasploitModule < Msf::Auxiliary
 # 這表示此模組繼承自 Msf::Auxiliary
 # 這是 Metasploit 提供的基底類別，用於輔助模組的定義。
 # 輔助模組通常不涉及漏洞利用，而是用來執行掃描、檢測、或其他非侵入性行為。

  def initialize(info = {})
   # initialize 方法用於定義模組的基本資訊，例如名稱、描述、作者、動作列表以及其他相關設定。

    super(
      # 每個參數都用逗號隔開，都用 "=>" 賦值
      # 至於 super、update_info、info 是什麼，是比較複雜的，暫時不解釋，
      # 但總之是跟框架有關的聯繫，有了這些關鍵字，
      # 這個模組就能去利用metasploit框架提供的基礎設施、底層功能。
      update_info(

        info,

        'Name' => 'Sample Auxiliary Module',

        # The description can be multiple lines, but does not preserve formatting.
        'Description' => 'Sample Auxiliary Module',

        'Author' => ['Joe Module <joem@example.com>'],

        'License' => MSF_LICENSE,

        # 模組可以執行的動作列表
        'Actions' => [
          # 執行預設動作
          [ 'Default Action', { 'Description' => 'This does something' } ],
          # 執行另一種動作
          [ 'Another Action', { 'Description' => 'This does a different thing' } ]
        ],

        # The action(s) that will run as background job
        # 可以作為背景作業執行的動作
        'PassiveActions' => [
          'Another Action'
        ],

        # https://docs.metasploit.com/docs/development/developing-modules/module-metadata/definition-of-module-reliability-side-effects-and-stability.html
        # 描述模組的穩定性、可靠性，以及可能的副作用。
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        },

        # 指定模組的預設動作
        'DefaultAction' => 'Default Action'
      )
    )

  end

  # 模組執行的核心邏輯，當使用者選擇某個動作時，框架會呼叫這個方法。
  # 範例中，它會輸出目前執行的動作名稱。
  def run
    print_status("Running the simple auxiliary module with action #{action.name}")
  end

  # Metasploit 框架會自動註冊所有以 cmd_ 開頭命名的方法，並將它們作為可以在主控台中執行的命令。
  # 方法名稱的結尾部分(例如 aux_extra_command)會被視為命令名稱。
  # 當使用者在 Metasploit 控制台中輸入這個命令時，框架會自動調用對應的 cmd_* 方法。
  def cmd_aux_extra_command(*args)
    print_status("Running inside aux_extra_command(#{args.join(' ')})")
  end




end
