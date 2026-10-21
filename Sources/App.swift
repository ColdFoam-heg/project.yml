import SwiftUI
import UIKit
import CryptoKit
import UniformTypeIdentifiers

// MARK: - 0. UIKit 文件选择器（绕开 SwiftUI fileImporter 同页多实例冲突导致的点击无反应）
final class DocumentPickerPresenter: NSObject, UIDocumentPickerDelegate {
    static let shared = DocumentPickerPresenter()
    private var completion: ((URL?) -> Void)?

    func pick(types: [UTType], asCopy: Bool = true, completion: @escaping (URL?) -> Void) {
        self.completion = completion
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: types, asCopy: asCopy)
        picker.delegate = self
        picker.allowsMultipleSelection = false
        guard let presenter = Self.topViewController() else {
            self.completion = nil
            completion(nil)
            return
        }
        presenter.present(picker, animated: true)
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        let handler = completion
        completion = nil
        handler?(urls.first)
    }

    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        let handler = completion
        completion = nil
        handler?(nil)
    }

    private static func topViewController() -> UIViewController? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        let window = scenes.flatMap { $0.windows }.first { $0.isKeyWindow } ?? scenes.flatMap { $0.windows }.first
        var top = window?.rootViewController
        while let presented = top?.presentedViewController { top = presented }
        return top
    }
}

// MARK: - 1. 安全二进制读取扩展
extension Data {
    func readUInt16LE(at offset: Int) -> UInt16 {
        guard offset >= 0, offset + 2 <= count else { return 0 }
        return UInt16(self[offset]) | (UInt16(self[offset + 1]) << 8)
    }

    func readUInt32LE(at offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= count else { return 0 }
        return UInt32(self[offset]) |
               (UInt32(self[offset + 1]) << 8) |
               (UInt32(self[offset + 2]) << 16) |
               (UInt32(self[offset + 3]) << 24)
    }

    var sha1Hex: String {
        let digest = Insecure.SHA1.hash(data: self)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - 2. 存档透视眼与 A/B 双槽校验模型
struct SaveInspectionResult {
    var fileName: String
    var fileSize: Int
    var isValidBatterySave: Bool
    var warningMessage: String?
    var isGen3PokemonFormat: Bool = false

    // Gen 3 128KB 专属信息
    var activeSlotName: String = "未知"
    var slotAValidSectors: Int = 0
    var slotBValidSectors: Int = 0
    var slotASaveIndex: UInt32 = 0
    var slotBSaveIndex: UInt32 = 0
    var playTimeText: String = "--:--:--"
    var trainerPublicID: UInt16 = 0
    var trainerSecretID: UInt16 = 0
}

class GBASaveEngine {
    // 宝可梦第三世代（绿宝石/火红等）14个扇区的标准校验长度表
    static let gen3SectorSizes: [Int] = [
        3884, 3968, 3968, 3968, 3848, 3968, 3968,
        3968, 3968, 3968, 3968, 3968, 3968, 2000
    ]

    static func inspect(data: Data, fileName: String) -> SaveInspectionResult {
        let size = data.count
        let lowerName = fileName.lowercased()

        // 1. 拦截 .svs 即时存档或异常文件大小
        if lowerName.hasSuffix(".svs") || (size != 32768 && size != 65536 && size != 131072) {
            return SaveInspectionResult(
                fileName: fileName,
                fileSize: size,
                isValidBatterySave: false,
                warningMessage: "⚠️ 检测到非标准电池存档（当前大小 \(size) 字节）！\n如果这是模拟器即时存档（.svs），跨版本串档必黑屏死机！请先在旧版游戏内菜单点「保存/记录」，再导出 64KB 或 128KB 的 .sav 电池存档。"
            )
        }

        var result = SaveInspectionResult(
            fileName: fileName,
            fileSize: size,
            isValidBatterySave: true,
            warningMessage: nil
        )

        // 2. 如果是 128KB (131,072 字节)，启动 A/B 双槽深度解析
        if size == 131072 {
            let slotAInfo = inspectSlot(data: data, baseOffset: 0x00000)
            // 标准布局：A 槽在 0x00000，中间 0xE000–0xFFFF 是名人堂等额外扇区，B 槽在 0x10000
            let slotBInfo = inspectSlot(data: data, baseOffset: 0x10000)

            if slotAInfo.validCount > 0 || slotBInfo.validCount > 0 {
                result.isGen3PokemonFormat = true
                result.slotAValidSectors = slotAInfo.validCount
                result.slotBValidSectors = slotBInfo.validCount
                result.slotASaveIndex = slotAInfo.saveIndex
                result.slotBSaveIndex = slotBInfo.saveIndex

                // 判断哪个槽是最新存档
                let useSlotA: Bool
                if slotAInfo.validCount == 14 && slotBInfo.validCount < 14 {
                    useSlotA = true
                } else if slotBInfo.validCount == 14 && slotAInfo.validCount < 14 {
                    useSlotA = false
                } else {
                    useSlotA = slotAInfo.saveIndex >= slotBInfo.saveIndex
                }

                result.activeSlotName = useSlotA ? "A 槽 (主档)" : "B 槽 (备档)"
                let activeInfo = useSlotA ? slotAInfo : slotBInfo
                result.playTimeText = activeInfo.playTime
                result.trainerPublicID = activeInfo.publicID
                result.trainerSecretID = activeInfo.secretID

                if slotAInfo.validCount < 14 && slotBInfo.validCount == 14 {
                    result.warningMessage = "检测到 A 槽有扇区损坏，但 B 槽完整！建议点击下方「一键修复双槽」避免进游戏掉档。"
                } else if slotBInfo.validCount < 14 && slotAInfo.validCount == 14 {
                    result.warningMessage = "检测到 B 槽备份区不完整，A 槽完好，可点击「一键同步修复双槽」加固存档。"
                }
            }
        }

        return result
    }

    private static func inspectSlot(data: Data, baseOffset: Int) -> (validCount: Int, saveIndex: UInt32, playTime: String, publicID: UInt16, secretID: UInt16) {
        var validSectors = 0
        var maxSaveIndex: UInt32 = 0
        var playTime = "--:--:--"
        var pubID: UInt16 = 0
        var secID: UInt16 = 0

        for i in 0..<14 {
            let sectorOffset = baseOffset + i * 0x1000
            let sectionID = Int(data.readUInt16LE(at: sectorOffset + 0x0FF4))
            let storedChecksum = data.readUInt16LE(at: sectorOffset + 0x0FF6)
            let signature = data.readUInt32LE(at: sectorOffset + 0x0FF8)
            let saveIndex = data.readUInt32LE(at: sectorOffset + 0x0FFC)

            guard signature == 0x08012025, sectionID >= 0, sectionID < 14 else { continue }

            // 校验扇区 Checksum
            let calcLength = gen3SectorSizes[sectionID]
            let calculated = calculateGen3Checksum(data: data, offset: sectorOffset, length: calcLength)
            if calculated == storedChecksum {
                validSectors += 1
            }

            if saveIndex != 0xFFFFFFFF && saveIndex >= maxSaveIndex {
                maxSaveIndex = saveIndex
            }

            // Section 0 存放主角信息与游戏时长
            if sectionID == 0 {
                pubID = data.readUInt16LE(at: sectorOffset + 0x000A)
                secID = data.readUInt16LE(at: sectorOffset + 0x000C)
                let hours = data.readUInt16LE(at: sectorOffset + 0x000E)
                let minutes = data[sectorOffset + 0x0010]
                let seconds = data[sectorOffset + 0x0011]
                playTime = String(format: "%02d小时 %02d分 %02d秒", hours, minutes, seconds)
            }
        }

        return (validSectors, maxSaveIndex, playTime, pubID, secID)
    }

    static func calculateGen3Checksum(data: Data, offset: Int, length: Int) -> UInt16 {
        var sum: UInt32 = 0
        let wordCount = length / 4
        for i in 0..<wordCount {
            sum = sum &+ data.readUInt32LE(at: offset + i * 4)
        }
        let folded = (sum & 0xFFFF) &+ (sum >> 16)
        return UInt16(folded & 0xFFFF)
    }

    // 一键双槽互备修复：将完好的槽（14 个扇区）复制到另一个槽
    // 标准布局：A 槽 = 0x00000–0x0DFFF，B 槽 = 0x10000–0x1DFFF，中间与末尾的额外扇区（名人堂等）绝不触碰
    static func repairDualSlot(data: Data, copySlotAToB: Bool) -> Data {
        guard data.count == 131072 else { return data }
        var repaired = data
        let slotSize = 0x0E000 // 57,344 字节 (14个扇区)
        if copySlotAToB {
            let slotAData = repaired.subdata(in: 0..<slotSize)
            repaired.replaceSubrange(0x10000..<(0x10000 + slotSize), with: slotAData)
        } else {
            let slotBData = repaired.subdata(in: 0x10000..<(0x10000 + slotSize))
            repaired.replaceSubrange(0..<slotSize, with: slotBData)
        }
        return repaired
    }

    // IPS 补丁合成器
    static func applyIPSPatch(romData: Data, patchData: Data) throws -> Data {
        guard patchData.count >= 8,
              String(data: patchData.subdata(in: 0..<5), encoding: .ascii) == "PATCH" else {
            throw NSError(domain: "IPS", code: 1, userInfo: [NSLocalizedDescriptionKey: "不是有效的 .ips 补丁文件（缺少 PATCH 文件头）"])
        }

        var output = romData
        var offset = 5

        while offset + 3 <= patchData.count {
            if String(data: patchData.subdata(in: offset..<(offset + 3)), encoding: .ascii) == "EOF" {
                break
            }
            let targetOffset = (Int(patchData[offset]) << 16) | (Int(patchData[offset + 1]) << 8) | Int(patchData[offset + 2])
            offset += 3
            guard offset + 2 <= patchData.count else { break }
            let length = (Int(patchData[offset]) << 8) | Int(patchData[offset + 1])
            offset += 2

            if length == 0 {
                // RLE 压缩块
                guard offset + 3 <= patchData.count else { break }
                let rleLength = (Int(patchData[offset]) << 8) | Int(patchData[offset + 1])
                let byteValue = patchData[offset + 2]
                offset += 3
                if targetOffset + rleLength > output.count {
                    output.append(Data(repeating: 0xFF, count: targetOffset + rleLength - output.count))
                }
                output.replaceSubrange(targetOffset..<(targetOffset + rleLength), with: Data(repeating: byteValue, count: rleLength))
            } else {
                // 普通数据块
                guard offset + length <= patchData.count else { break }
                let chunk = patchData.subdata(in: offset..<(offset + length))
                offset += length
                if targetOffset + length > output.count {
                    output.append(Data(repeating: 0xFF, count: targetOffset + length - output.count))
                }
                output.replaceSubrange(targetOffset..<(targetOffset + length), with: chunk)
            }
        }
        return output
    }
}

// MARK: - 3. 时光机备份模型与管理
struct BackupRecord: Identifiable, Codable {
    var id = UUID()
    var title: String
    var romSHA1: String
    var createdAt: Date
    var fileName: String
    var playTimeSummary: String
}

class AppViewModel: ObservableObject {
    @Published var oldSaveData: Data?
    @Published var oldSaveName: String = ""
    @Published var saveInspection: SaveInspectionResult?

    @Published var newRomData: Data?
    @Published var newRomName: String = ""
    @Published var newRomSHA1: String = ""
    @Published var newRomInternalTitle: String = ""

    @Published var deltaFolderBookmark: Data?
    @Published var deltaFolderName: String = "未绑定（点击绑定 Delta/Database 目录）"
    @Published var romSaveChipText: String = ""
    @Published var bindDebugText: String = "绑定状态：尚未尝试"

    @Published var backups: [BackupRecord] = []
    @Published var statusMessage: String = "准备就绪：请先导入旧版 .sav 存档与新版 .gba 游戏"
    @Published var showAlert: Bool = false
    @Published var alertTitle: String = ""
    @Published var alertBody: String = ""

    private let backupMetaURL: URL
    private let backupDirURL: URL

    init() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        backupDirURL = docs.appendingPathComponent("TimeMachineBackups", isDirectory: true)
        backupMetaURL = docs.appendingPathComponent("backups.json")
        try? FileManager.default.createDirectory(at: backupDirURL, withIntermediateDirectories: true)
        loadBackups()
        loadDeltaBookmark()
    }

    func importSaveFile(url: URL) {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        do {
            let data = try Data(contentsOf: url)
            self.oldSaveData = data
            self.oldSaveName = url.lastPathComponent
            let inspection = GBASaveEngine.inspect(data: data, fileName: url.lastPathComponent)
            self.saveInspection = inspection

            if let warn = inspection.warningMessage {
                triggerAlert(title: "存档体检提醒", body: warn)
            } else {
                triggerAlert(title: "✅ 存档导入成功", body: "已加载「\(url.lastPathComponent)」\n大小：\(data.count / 1024) KB")
            }
            statusMessage = "已加载存档：\(url.lastPathComponent)"
        } catch {
            triggerAlert(title: "读取存档失败", body: error.localizedDescription)
        }
    }

    func importRomFile(url: URL) {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        do {
            let data = try Data(contentsOf: url)
            loadNewRomData(data: data, name: url.lastPathComponent)
            triggerAlert(title: "✅ 游戏导入成功", body: "已加载「\(url.lastPathComponent)」\n大小：\(data.count / 1024) KB\nDelta SHA-1：\(data.sha1Hex)")
        } catch {
            triggerAlert(title: "读取 GBA 游戏失败", body: error.localizedDescription)
        }
    }

    func loadNewRomData(data: Data, name: String) {
        self.newRomData = data
        self.newRomName = name
        self.newRomSHA1 = data.sha1Hex
        self.romSaveChipText = Self.detectRomSaveChip(data: data)
        // 读取 GBA 卡带头部 0xA0 处的 12 字节内部英文标识
        if data.count >= 0xAC {
            let headerSlice = data.subdata(in: 0xA0..<0xAC)
            self.newRomInternalTitle = String(data: headerSlice, encoding: .ascii)?.trimmingCharacters(in: .controlCharacters) ?? "GBA_ROM"
        }
        statusMessage = "已计算新版游戏 SHA-1 特征码"
    }

    // 扫描 ROM 内部的存档芯片标记（GBA 游戏靠这串字符声明自己用哪种存档芯片）
    static func detectRomSaveChip(data: Data) -> String {
        let markers: [(String, String)] = [
            ("FLASH1M_V", "Flash 128KB（FLASH1M）"),
            ("FLASH512_V", "Flash 64KB（FLASH512）"),
            ("FLASH_V", "Flash 64KB"),
            ("SRAM_V", "SRAM 32KB"),
            ("EEPROM_V", "EEPROM 小容量")
        ]
        for (marker, label) in markers {
            if data.range(of: Data(marker.utf8)) != nil { return label }
        }
        return "未找到存档芯片标记"
    }

    // 导出前的大白话体检结论（存档与新游戏都选好后才有）
    var migrationVerdict: String? {
        guard let info = saveInspection, newRomData != nil else { return nil }
        guard info.isGen3PokemonFormat else {
            return "这份存档不是标准的宝可梦 128KB 双槽格式，没法做槽位体检。导出的文件与原档完全一致，能不能读取决于新游戏本身是否兼容这份存档。\n小提示：把存档放进 Delta 之前，先把 Delta 从后台彻底划掉关掉，再替换文件，最后重新打开。"
        }
        let a = info.slotAValidSectors
        let b = info.slotBValidSectors
        let latestIsA = info.slotASaveIndex >= info.slotBSaveIndex
        var lines: [String] = []
        if a == 14 && b == 14 {
            lines.append("✅ 存档体检：A、B 两个槽都是完好的（14/14）。导出的文件和原档一模一样，新游戏正常情况下能直接读到最新进度。")
        } else if a < 14 && b < 14 {
            lines.append("❌ 存档体检：A、B 两个槽都有扇区损坏（A 槽 \(a)/14，B 槽 \(b)/14）。这份存档本身已经不完整，串到哪个游戏都会报错。建议回旧游戏里重新保存一次，再拿新的 .sav 来串。")
        } else if a < 14 {
            if latestIsA {
                lines.append("⚠️ 存档体检：最新那份存档在 A 槽，它有扇区损坏（\(a)/14），B 槽是完好的。这正是新游戏提示「存档已损坏」的原因 — 它会改读上一次的进度。可以去「存档透视与修复」页用完好的 B 槽修复后再导出，就不会再报错（进度是上一次保存的）。")
            } else {
                lines.append("✅ 存档体检：最新那份存档（B 槽）是完好的（14/14），可以放心串档。A 槽有点小毛病不影响使用，想加固可以去修复页同步一下。")
            }
        } else {
            if latestIsA {
                lines.append("✅ 存档体检：最新那份存档（A 槽）是完好的（14/14），可以放心串档。B 槽有点小毛病不影响使用，想加固可以去修复页同步一下。")
            } else {
                lines.append("⚠️ 存档体检：最新那份存档在 B 槽，它有扇区损坏（\(b)/14），A 槽是完好的。这正是新游戏提示「存档已损坏」的原因 — 它会改读上一次的进度。可以去「存档透视与修复」页用完好的 A 槽修复后再导出，就不会再报错（进度是上一次保存的）。")
            }
        }
        if romSaveChipText.hasPrefix("未找到") {
            lines.append("⚠️ 另外：新游戏里没找到存档芯片标记，它可能认不出 128KB 存档 — 这种情况游戏也会报「存档已损坏」，属于游戏 ROM 本身的问题，换个来源的 ROM 再试。")
        } else if !romSaveChipText.isEmpty && !romSaveChipText.contains("128KB") {
            lines.append("⚠️ 另外：新游戏标记的存档芯片是「\(romSaveChipText)」，不是 128KB 类型，和这份 128KB 存档对不上，游戏大概率会报存档已损坏。")
        }
        lines.append("小提示：把存档放进 Delta 之前，先把 Delta 从后台彻底划掉关掉，再替换文件，最后重新打开 — 游戏开着的时候换存档容易读错。")
        return lines.joined(separator: "\n")
    }

    // 备用绑定：用户选 Database 文件夹里的任意一个文件，反推文件夹并当场做写入测试
    func bindDeltaFolderByFile(url: URL) {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        let folderURL = url.deletingLastPathComponent()
        do {
            // 先做真实写入测试：建 Games 目录、写探针文件再删掉
            let gamesURL = folderURL.appendingPathComponent("Games", isDirectory: true)
            try FileManager.default.createDirectory(at: gamesURL, withIntermediateDirectories: true)
            let probe = gamesURL.appendingPathComponent(".lengmo_probe")
            try Data([0x4C]).write(to: probe)
            try FileManager.default.removeItem(at: probe)
            // 写入没问题，再存文件夹书签供以后注入使用
            let bookmark = try folderURL.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
            UserDefaults.standard.set(bookmark, forKey: "DeltaDatabaseBookmark")
            self.deltaFolderBookmark = bookmark
            self.deltaFolderName = "已绑定：\(folderURL.lastPathComponent)"
            bindDebugText = "绑定状态：选文件绑定成功（\(folderURL.lastPathComponent)），写入测试通过"
            triggerAlert(title: "✅ 绑定成功", body: "已通过你选的文件反推绑定「\(folderURL.lastPathComponent)」文件夹，并通过了实际写入测试，现在可以一键注入了。")
        } catch {
            bindDebugText = "绑定状态：选文件绑定失败 — \(error.localizedDescription)"
            triggerAlert(title: "选文件绑定失败", body: "拿到了文件「\(url.lastPathComponent)」，但没能取得它所在文件夹的写入权限。\n\n请改用文件夹绑定：走进 Database 文件夹后，点右上角蓝色的 Open 按钮。\n错误详情：\(error.localizedDescription)")
        }
    }

    // 自动备份进时光机
    func createBackup(data: Data, tagTitle: String) {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd_HHmmss"
        let fileName = "Backup_\(formatter.string(from: Date())).sav"
        let fileURL = backupDirURL.appendingPathComponent(fileName)
        do {
            try data.write(to: fileURL)
            let record = BackupRecord(
                title: tagTitle,
                romSHA1: newRomSHA1.isEmpty ? "手动备份" : newRomSHA1,
                createdAt: Date(),
                fileName: fileName,
                playTimeSummary: saveInspection?.playTimeText ?? "\(data.count / 1024) KB"
            )
            backups.insert(record, at: 0)
            saveBackups()
        } catch {
            print("Backup error: \(error)")
        }
    }

    func getBackupFileURL(record: BackupRecord) -> URL {
        return backupDirURL.appendingPathComponent(record.fileName)
    }

    // 生成配对好的双文件供导出（同名 .sav + Delta SHA1 .sav）
    func exportPairedFiles() -> [URL] {
        guard let save = oldSaveData, let rom = newRomData else { return [] }
        createBackup(data: save, tagTitle: "串档前自动备份 - \(oldSaveName)")

        let tempDir = FileManager.default.temporaryDirectory
        let baseRomName = (newRomName as NSString).deletingPathExtension

        // 1. 同名 .sav（方便常规导入或其它模拟器）
        let sameNameSavURL = tempDir.appendingPathComponent("\(baseRomName).sav")
        // 2. Delta 专属 SHA-1 特征码 .sav
        let sha1SavURL = tempDir.appendingPathComponent("\(newRomSHA1).sav")
        // 3. 新版游戏 .gba
        let romURL = tempDir.appendingPathComponent(newRomName)

        try? save.write(to: sameNameSavURL)
        try? save.write(to: sha1SavURL)
        try? rom.write(to: romURL)

        return [sameNameSavURL, sha1SavURL, romURL]
    }

    // 绑定 Delta Database 文件夹
    func bindDeltaDatabaseFolder(url: URL) {
        let accessed = url.startAccessingSecurityScopedResource()
        defer { if accessed { url.stopAccessingSecurityScopedResource() } }
        do {
            let bookmark = try url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
            UserDefaults.standard.set(bookmark, forKey: "DeltaDatabaseBookmark")
            self.deltaFolderBookmark = bookmark
            self.deltaFolderName = "已绑定：\(url.lastPathComponent)"
            bindDebugText = "绑定状态：文件夹绑定成功（\(url.lastPathComponent)）"
            triggerAlert(title: "✅ Delta 目录绑定成功", body: "已绑定文件夹「\(url.lastPathComponent)」，现在可以一键直连注入了。")
        } catch {
            bindDebugText = "绑定状态：文件夹绑定失败 — \(error.localizedDescription)"
            triggerAlert(title: "目录授权失败", body: error.localizedDescription)
        }
    }

    private func loadDeltaBookmark() {
        if let bm = UserDefaults.standard.data(forKey: "DeltaDatabaseBookmark") {
            self.deltaFolderBookmark = bm
            self.deltaFolderName = "已绑定 Delta 目录（可一键直连注入）"
        }
    }

    // 直连 Delta 文件夹一键注入存档 + 清理冲突即时存档
    func injectIntoDeltaDatabase(cleanAutoSaveStates: Bool) {
        guard let save = oldSaveData, let rom = newRomData, !newRomSHA1.isEmpty else {
            triggerAlert(title: "缺少文件", body: "请先选择旧版 .sav 存档和新版 .gba 游戏！")
            return
        }
        guard let bookmark = deltaFolderBookmark else {
            triggerAlert(title: "尚未绑定 Delta 目录", body: "请先点击「绑定 Delta/Database 文件夹」授权访问。")
            return
        }

        var isStale = false
        do {
            let folderURL = try URL(resolvingBookmarkData: bookmark, bookmarkDataIsStale: &isStale)
            let accessed = folderURL.startAccessingSecurityScopedResource()
            defer { if accessed { folderURL.stopAccessingSecurityScopedResource() } }

            // 判断用户选的是 Delta 根目录、Database 目录还是 Games 目录
            let gamesDir: URL
            if folderURL.lastPathComponent == "Games" {
                gamesDir = folderURL
            } else if folderURL.lastPathComponent == "Database" {
                gamesDir = folderURL.appendingPathComponent("Games", isDirectory: true)
            } else {
                gamesDir = folderURL.appendingPathComponent("Database/Games", isDirectory: true)
            }

            try FileManager.default.createDirectory(at: gamesDir, withIntermediateDirectories: true)

            let targetRomURL = gamesDir.appendingPathComponent("\(newRomSHA1).gba")
            let targetSavURL = gamesDir.appendingPathComponent("\(newRomSHA1).sav")

            // 如果原本已有存档，先备份到时光机
            if let existingSav = try? Data(contentsOf: targetSavURL) {
                createBackup(data: existingSav, tagTitle: "Delta原存档覆盖前备份 - \(newRomName)")
            } else {
                createBackup(data: save, tagTitle: "直连串档备份 - \(oldSaveName)")
            }

            // 写入新版 ROM 和配对好的 SHA-1 存档
            try rom.write(to: targetRomURL, options: .atomic)
            try save.write(to: targetSavURL, options: .atomic)

            // 可选：清理该 SHA-1 下的即时存档，防止 Delta 自动加载旧即时存档覆盖新电池存档
            var cleanedCount = 0
            if cleanAutoSaveStates {
                let saveStatesDir = gamesDir.deletingLastPathComponent().appendingPathComponent("Save States/\(newRomSHA1)", isDirectory: true)
                if let files = try? FileManager.default.contentsOfDirectory(at: saveStatesDir, includingPropertiesForKeys: nil) {
                    for f in files {
                        try? FileManager.default.removeItem(at: f)
                        cleanedCount += 1
                    }
                }
            }

            triggerAlert(
                title: "🎉 一键直连串档成功！",
                body: "已将存档精准注入 Delta 数据库：\n文件特征码：\(newRomSHA1).sav\n清理冲突即时存档：\(cleanedCount) 个\n\n现在直接打开 Delta 模拟器，从游戏内标题界面点击「继续游戏」即可无缝继承进度！"
            )
        } catch {
            triggerAlert(title: "直连注入失败", body: "请重新绑定 Delta/Database 文件夹后再试。\n错误详情：\(error.localizedDescription)")
        }
    }

    func repairCurrentSave(copyAToB: Bool) {
        guard let save = oldSaveData else { return }
        createBackup(data: save, tagTitle: "双槽修复前备份 - \(oldSaveName)")
        let repaired = GBASaveEngine.repairDualSlot(data: save, copySlotAToB: copyAToB)
        self.oldSaveData = repaired
        self.saveInspection = GBASaveEngine.inspect(data: repaired, fileName: oldSaveName)
        triggerAlert(title: "双槽修复完成", body: (copyAToB ? "已将 A 槽完整数据同步至 B 槽！" : "已用 B 槽备份数据成功恢复 A 槽！") + "\n修复只改了 App 里的这份存档，记得回「一键串档」页重新导出配对文件再进游戏。")
    }

    func triggerAlert(title: String, body: String) {
        self.alertTitle = title
        self.alertBody = body
        self.showAlert = true
    }

    private func saveBackups() {
        if let encoded = try? JSONEncoder().encode(backups) {
            try? encoded.write(to: backupMetaURL)
        }
    }

    private func loadBackups() {
        if let data = try? Data(contentsOf: backupMetaURL),
           let decoded = try? JSONDecoder().decode([BackupRecord].self, from: data) {
            self.backups = decoded
        }
    }
}

// MARK: - 4. 系统分享弹窗封装
struct ShareSheet: UIViewControllerRepresentable {
    var items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

// MARK: - 5. 主界面视图
@main
struct GBASaveMasterApp: App {
    @StateObject private var vm = AppViewModel()
    var body: some Scene {
        WindowGroup {
            MainTabView()
                .environmentObject(vm)
        }
    }
}

struct MainTabView: View {
    @EnvironmentObject var vm: AppViewModel

    var body: some View {
        TabView {
            MigrationView()
                .tabItem {
                    Label("一键串档", systemImage: "arrow.triangle.2.circlepath.circle.fill")
                }

            InspectorView()
                .tabItem {
                    Label("存档透视与修复", systemImage: "magnifyingglass.circle.fill")
                }

            PatcherView()
                .tabItem {
                    Label("补丁合成", systemImage: "hammer.circle.fill")
                }

            TimeMachineView()
                .tabItem {
                    Label("时光机备份", systemImage: "clock.arrow.circlepath")
                }
        }
        .alert(isPresented: $vm.showAlert) {
            Alert(title: Text(vm.alertTitle), message: Text(vm.alertBody), dismissButton: .default(Text("知道了")))
        }
    }
}

// MARK: - Tab 1: 一键串档与 Delta 直连页面
struct MigrationView: View {
    @EnvironmentObject var vm: AppViewModel
    @State private var cleanAutoStates = true
    @State private var showShareSheet = false
    @State private var shareItems: [Any] = []

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("第一步：选择旧版存档 (.sav)")) {
                    Button(action: {
                        DocumentPickerPresenter.shared.pick(types: [.data, .item]) { url in
                            if let url = url { vm.importSaveFile(url: url) }
                        }
                    }) {
                        HStack {
                            Image(systemName: vm.oldSaveData == nil ? "doc.badge.plus" : "checkmark.seal.fill")
                                .foregroundColor(vm.oldSaveData == nil ? .blue : .green)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(vm.oldSaveName.isEmpty ? "点击导入旧版本存档 (.sav)" : vm.oldSaveName)
                                    .font(.headline)
                                if let info = vm.saveInspection {
                                    Text("大小: \(info.fileSize / 1024) KB | 游戏时长: \(info.playTimeText)")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                            }
                        }
                    }
                }

                Section(header: Text("第二步：选择新版游戏 (.gba)")) {
                    Button(action: {
                        DocumentPickerPresenter.shared.pick(types: [.data, .item]) { url in
                            if let url = url { vm.importRomFile(url: url) }
                        }
                    }) {
                        HStack {
                            Image(systemName: vm.newRomData == nil ? "gamecontroller.fill" : "checkmark.seal.fill")
                                .foregroundColor(vm.newRomData == nil ? .orange : .green)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(vm.newRomName.isEmpty ? "点击导入新版本游戏 (.gba)" : vm.newRomName)
                                    .font(.headline)
                                if !vm.newRomSHA1.isEmpty {
                                    Text("Delta SHA-1: \(vm.newRomSHA1.prefix(16))...")
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                }
                                if !vm.romSaveChipText.isEmpty {
                                    Text("存档芯片标记: \(vm.romSaveChipText)")
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                }
                            }
                        }
                    }
                }

                Section(header: Text("第三步（方式 A）：Delta 数据库文件夹一键直连"),
                        footer: Text("绑定方法：点第一个按钮 → 找到「我的 iPhone → Delta → Database」→ 点进这个文件夹 → 点右上角蓝色的 Open。如果点 Open 没反应，用备用方法：选 Database 里的 Delta.sqlite 文件，App 会自己反推文件夹并当场测能不能写入。")) {
                    Button(action: {
                        DocumentPickerPresenter.shared.pick(types: [.folder], asCopy: false) { url in
                            if let url = url {
                                vm.bindDeltaDatabaseFolder(url: url)
                            } else {
                                vm.bindDebugText = "绑定状态：文件夹选择被取消，没收到文件夹（记得走进 Database 后点右上角 Open）"
                            }
                        }
                    }) {
                        Label(vm.deltaFolderName, systemImage: "folder.fill.badge.gearshape")
                    }

                    Button(action: {
                        DocumentPickerPresenter.shared.pick(types: [.data, .item], asCopy: false) { url in
                            if let url = url {
                                vm.bindDeltaFolderByFile(url: url)
                            } else {
                                vm.bindDebugText = "绑定状态：文件选择被取消"
                            }
                        }
                    }) {
                        Label("备用方法：选 Database 里的文件来绑定", systemImage: "doc.badge.gearshape")
                    }

                    Text(vm.bindDebugText)
                        .font(.caption)
                        .foregroundColor(.secondary)

                    Toggle("顺手清理新版自动即时存档（防冲突）", isOn: $cleanAutoStates)

                    Button(action: {
                        vm.injectIntoDeltaDatabase(cleanAutoSaveStates: cleanAutoStates)
                    }) {
                        HStack {
                            Spacer()
                            Image(systemName: "bolt.horizontal.circle.fill")
                            Text("一键直连注入 Delta 数据库")
                                .bold()
                            Spacer()
                        }
                    }
                    .disabled(vm.oldSaveData == nil || vm.newRomData == nil)
                    .foregroundColor(.white)
                    .listRowBackground((vm.oldSaveData != nil && vm.newRomData != nil) ? Color.blue : Color.gray)
                }

                Section(header: Text("第三步（方式 B）：导出配对好的同名与特征码存档"),
                        footer: Text("同时生成「新版同名.sav」与「Delta特征码.sav」，并自动在时光机里备份原存档。")) {
                    Button(action: {
                        shareItems = vm.exportPairedFiles()
                        if !shareItems.isEmpty { showShareSheet = true }
                    }) {
                        HStack {
                            Spacer()
                            Image(systemName: "square.and.arrow.up.fill")
                            Text("一键生成并导出配对文件")
                                .bold()
                            Spacer()
                        }
                    }
                    .disabled(vm.oldSaveData == nil || vm.newRomData == nil)

                    if let verdict = vm.migrationVerdict {
                        Text(verdict)
                            .font(.footnote)
                            .foregroundColor(.secondary)
                    }
                }

                Section {
                    HStack {
                        Spacer()
                        Text("GBA 串档神器 · 开发者 LengMo")
                            .font(.footnote)
                            .foregroundColor(.secondary)
                        Spacer()
                    }
                }
            }
            .navigationTitle("GBA 串档神器")
            .sheet(isPresented: $showShareSheet) {
                ShareSheet(items: shareItems)
            }
        }
    }
}

// MARK: - Tab 2: 存档透视眼与 A/B 双槽修复页面
struct InspectorView: View {
    @EnvironmentObject var vm: AppViewModel

    var body: some View {
        NavigationView {
            List {
                if let info = vm.saveInspection {
                    Section(header: Text("基础文件诊断")) {
                        HStack { Text("文件名"); Spacer(); Text(info.fileName).foregroundColor(.secondary) }
                        HStack { Text("文件体积"); Spacer(); Text("\(info.fileSize) 字节 (\(info.fileSize / 1024) KB)").foregroundColor(.secondary) }
                        HStack {
                            Text("电池存档合规性")
                            Spacer()
                            Text(info.isValidBatterySave ? "✅ 标准电池存档" : "❌ 异常/即时存档")
                                .foregroundColor(info.isValidBatterySave ? .green : .red)
                        }
                    }

                    if info.isGen3PokemonFormat {
                        Section(header: Text("存档内部数据透视 (128KB Flash)")) {
                            HStack { Text("当前生效槽位"); Spacer(); Text(info.activeSlotName).bold().foregroundColor(.blue) }
                            HStack { Text("游戏时长"); Spacer(); Text(info.playTimeText).bold() }
                            HStack { Text("训练家表 ID (TID)"); Spacer(); Text(String(format: "%05d", info.trainerPublicID)).foregroundColor(.secondary) }
                            HStack { Text("训练家里 ID (SID)"); Spacer(); Text(String(format: "%05d", info.trainerSecretID)).foregroundColor(.secondary) }
                        }

                        Section(header: Text("A / B 双槽扇区完整性校验"),
                                footer: Text("标准 128KB 存档由 A 槽与 B 槽各 14 个扇区组成。若某次保存闪退导致其中一个槽损坏，可用完好槽一键修复。")) {
                            HStack {
                                Text("A 槽状态 (保存次数: \(info.slotASaveIndex))")
                                Spacer()
                                Text("\(info.slotAValidSectors) / 14 扇区完好")
                                    .foregroundColor(info.slotAValidSectors == 14 ? .green : .orange)
                            }
                            HStack {
                                Text("B 槽状态 (保存次数: \(info.slotBSaveIndex))")
                                Spacer()
                                Text("\(info.slotBValidSectors) / 14 扇区完好")
                                    .foregroundColor(info.slotBValidSectors == 14 ? .green : .orange)
                            }

                            Button("用 A 槽数据覆盖修复 B 槽") {
                                vm.repairCurrentSave(copyAToB: true)
                            }
                            Button("用 B 槽备份恢复至 A 槽（回退上一次保存）") {
                                vm.repairCurrentSave(copyAToB: false)
                            }
                        }
                    }
                } else {
                    Text("请先在「一键串档」页面导入一个 .sav 存档文件，即可在此查看内部透视数据。")
                        .foregroundColor(.secondary)
                        .padding()
                }
            }
            .navigationTitle("存档透视眼")
        }
    }
}

// MARK: - Tab 3: 内置 .ips 补丁合成器
struct PatcherView: View {
    @EnvironmentObject var vm: AppViewModel
    @State private var baseRomData: Data?
    @State private var baseRomName: String = ""
    @State private var patchData: Data?
    @State private var patchName: String = ""


    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("1. 选择基础版 GBA 游戏 (.gba)")) {
                    Button(baseRomName.isEmpty ? "点击选择旧版/基础版 .gba" : baseRomName) {
                        DocumentPickerPresenter.shared.pick(types: [.data, .item]) { url in
                            guard let url = url else { return }
                            let acc = url.startAccessingSecurityScopedResource()
                            defer { if acc { url.stopAccessingSecurityScopedResource() } }
                            baseRomData = try? Data(contentsOf: url)
                            baseRomName = url.lastPathComponent
                        }
                    }
                }

                Section(header: Text("2. 选择升级补丁文件 (.ips)")) {
                    Button(patchName.isEmpty ? "点击选择 .ips 更新补丁" : patchName) {
                        DocumentPickerPresenter.shared.pick(types: [.data, .item]) { url in
                            guard let url = url else { return }
                            let acc = url.startAccessingSecurityScopedResource()
                            defer { if acc { url.stopAccessingSecurityScopedResource() } }
                            patchData = try? Data(contentsOf: url)
                            patchName = url.lastPathComponent
                        }
                    }
                }

                Section(footer: Text("合成成功后，新版 .gba 会自动填入「一键串档」页面并算好 Delta SHA-1 特征码。")) {
                    Button(action: {
                        guard let rom = baseRomData, let patch = patchData else { return }
                        do {
                            let patched = try GBASaveEngine.applyIPSPatch(romData: rom, patchData: patch)
                            let newName = (baseRomName as NSString).deletingPathExtension + "_Patched.gba"
                            vm.loadNewRomData(data: patched, name: newName)
                            vm.triggerAlert(title: "✅ 补丁合成成功！", body: "已生成新版游戏：\(newName)\nDelta SHA-1：\(patched.sha1Hex)\n\n已自动载入「一键串档」页面，可直接串档！")
                        } catch {
                            vm.triggerAlert(title: "补丁合成失败", body: error.localizedDescription)
                        }
                    }) {
                        HStack {
                            Spacer()
                            Text("一键合成新版 GBA 并准备串档").bold()
                            Spacer()
                        }
                    }
                    .disabled(baseRomData == nil || patchData == nil)
                }
            }
            .navigationTitle("内置补丁合成")
        }
    }
}

// MARK: - Tab 4: 时光机自动备份库
struct TimeMachineView: View {
    @EnvironmentObject var vm: AppViewModel
    @State private var showShare = false
    @State private var shareURL: URL?

    var body: some View {
        NavigationView {
            List {
                if vm.backups.isEmpty {
                    Text("暂无历史备份。每次执行串档或双槽修复前，系统都会自动将原始存档备份至此处。")
                        .foregroundColor(.secondary)
                        .padding()
                } else {
                    ForEach(vm.backups) { item in
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(item.title).font(.headline)
                                Text("时长/大小: \(item.playTimeSummary)").font(.caption).foregroundColor(.blue)
                                Text(item.createdAt, style: .date).font(.caption2).foregroundColor(.secondary)
                            }
                            Spacer()
                            Button(action: {
                                shareURL = vm.getBackupFileURL(record: item)
                                showShare = true
                            }) {
                                Image(systemName: "square.and.arrow.up")
                                    .padding(8)
                            }
                        }
                    }
                }
            }
            .navigationTitle("时光机备份库")
            .sheet(isPresented: $showShare) {
                if let url = shareURL {
                    ShareSheet(items: [url])
                }
            }
        }
    }
}
