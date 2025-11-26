**Prompt**

我需要你编写一个在 Windows 上运行的程序，用于可靠地记录所有“显示器插入/拔除”事件，适用于多显卡与多输出场景（例如使用带 4–5 个输出口的 NVIDIA 显卡，同时接 4–5 个显示器）。请按如下要求完成实现并给出完整可运行代码与说明。

- 平台与语言
  - 目标平台：Windows 10/11，x64。
  - 语言与框架：C++17/20，Win32 API，用户态程序，无需管理员权限。
  - 编译与构建：Visual Studio 2019（MSVC）或 CMake + MSVC；不使用 .NET。

- 事件监听与检测
  - 必须捕获以下类型的事件，并在每次事件发生时重新枚举当前活动显示器：
    - 设备层事件：`WM_DEVICECHANGE`（`DBT_DEVICEARRIVAL` / `DBT_DEVICEREMOVECOMPLETE`），通过 `RegisterDeviceNotification` 订阅 `GUID_DEVINTERFACE_MONITOR`。
    - 显示设置变化：`WM_DISPLAYCHANGE`、`WM_SETTINGCHANGE`（仅用于补充）。
    - WMI 事件作为冗余与增强：`Win32_DeviceChangeEvent` 以及对 `Win32_PnPEntity`（`PNPClass='Monitor'`）的 `__InstanceOperationEvent`。
  - 在每次事件回调中，用以下枚举方式获取最准确的连接信息：
    - 用 `QueryDisplayConfig(QDC_ONLY_ACTIVE_PATHS)` 获取 `DISPLAYCONFIG_PATH_INFO`。
    - 用 `DisplayConfigGetDeviceInfo(DISPLAYCONFIG_TARGET_DEVICE_NAME)` 获取显示器友好名与 `outputTechnology`（HDMI/DP/内部面板等）。
    - 记录 `adapterId`（LUID）和 `targetId` 用于定位显卡与具体输出端口。
    - 作为补充，使用 DXGI：枚举 `IDXGIAdapter` 与 `IDXGIOutput`，获取 `AdapterDesc`（VendorId/Description）与输出描述。

- 记录内容（事件日志字段）
  - 时间戳：ISO-8601（UTC），高精度到毫秒。
  - 动作：`connected` 或 `disconnected`。
  - 显卡信息：`adapterLuid`、`vendorId`、`adapterDescription`。
  - 输出端口信息：`targetId`、`outputTechnology`（枚举到 HDMI/DP/DVI/内部等）、显示路径的 `sourceId`/`displayName`（如 `\\.\DISPLAY1`）。
  - 显示器信息：友好名、`PNPDeviceID`、可能的 `EDID` 哈希（可通过注册表 `HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY` 读取并计算哈希），序列号（若可用）。
  - 拓扑提示：是否经扩展坞/USB（如 DisplayLink）、虚拟显示器（若检测到），原始接口类 GUID。
  - 可靠性要求：同一事件不重复记录（用 `adapterLuid+targetId+action` 去重 2 秒窗口）。

- 日志落盘
  - 写入 `C:\ProgramData\MonitorEvents\events.json`（若无则自动创建目录）。
  - 格式：每行一个 JSON（JSON Lines）。
  - 日志滚动：单文件最大 10MB，保留最近 5 个滚动文件。
  - 可选：同时写入 Windows 事件日志（`Application` 日志），便于企业审计。

- 运行形态
  - 提供两种形态：
    - 托盘应用（带最小 UI）：程序退出、日志位置打开。
    - 无界面常驻（服务或消息窗口）：用于静默部署。
  - 无界面形态需要有消息循环或消息-only 窗口以接收 `WM_DEVICECHANGE`。

- 健壮性与边界情况
  - 正确处理：同一显卡上的多个输出口同时插拔；多个显卡（如核显+独显）；扩展坞/USB 显示适配器；虚拟显示器。
  - 事件风暴抑制：对连续大量事件做 100–200ms 合并/去重。
  - 对读不到 EDID/序列号的情况容错，字段置空但不影响事件记录。
  - 程序异常与权限受限时，写入错误日志并继续运行。

- 交付物
  - 完整源码（C++ Win32），包含：
    - 事件监听（窗口类/消息循环 + `RegisterDeviceNotification`）、WMI 订阅（COM）、`QueryDisplayConfig`/DXGI 枚举。
    - 日志模块（JSON Lines + 滚动）。
    - 简单托盘 UI（可隐藏运行）。
    - 结构清晰的项目（`main.cpp`、事件采集器、枚举器、日志器、UI），使用 MSVC 或 CMake 组织。
  - 清晰的构建与运行说明（无需管理员），以及如何切换到无界面模式（消息-only 窗口或 Windows 服务）。
  - 单元/集成测试（若部分功能难以模拟，至少提供枚举与日志模块的可测试单元）。
  - 示例日志片段（包含多显卡多输出插拔的样例，展示字段完整性）。

- 验收标准
  - 插拔 4–5 个显示器（NVIDIA 多输出）时，能准确记录每一次 `connected/disconnected` 事件，并包含正确的显卡与输出端口信息（`adapterLuid` + `targetId` + `outputTechnology`）。
  - 日志连续、无重复、可在记事本/解析器中直接读取为 JSON Lines。
  - 程序运行稳定 ≥24 小时，不崩溃，不阻塞消息循环。

请直接给出：
1) 完整实现代码（C++ Win32），
2) 构建与运行步骤，
3) 简短说明各关键 API 的选择与权衡（`WM_DEVICECHANGE` vs WMI vs `QueryDisplayConfig`/DXGI），
4) 在多输出 NVIDIA 场景下的映射逻辑说明与已知局限。