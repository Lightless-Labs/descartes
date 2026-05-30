import Foundation
import UserNotifications

struct Arguments {
    var title = "Descartes alert"
    var body = "Descartes noticed a local system alert."
    var severity = "info"
    var alertId = ""
    var ruleId = ""
}

func parseArguments(_ raw: [String]) -> Arguments {
    var args = Arguments()
    var index = 0
    while index < raw.count {
        let key = raw[index]
        let value = index + 1 < raw.count ? raw[index + 1] : ""
        switch key {
        case "--title":
            args.title = value
            index += 2
        case "--body":
            args.body = value
            index += 2
        case "--severity":
            args.severity = value
            index += 2
        case "--alert-id":
            args.alertId = value
            index += 2
        case "--rule-id":
            args.ruleId = value
            index += 2
        default:
            index += 1
        }
    }
    return args
}

func bounded(_ value: String, max: Int, fallback: String) -> String {
    let collapsed = value.replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression).trimmingCharacters(in: .whitespacesAndNewlines)
    if collapsed.isEmpty { return fallback }
    if collapsed.count <= max { return collapsed }
    let end = collapsed.index(collapsed.startIndex, offsetBy: max)
    return String(collapsed[..<end]) + "…"
}

let args = parseArguments(Array(CommandLine.arguments.dropFirst()))
let center = UNUserNotificationCenter.current()
let semaphore = DispatchSemaphore(value: 0)
var exitCode: Int32 = 0

center.requestAuthorization(options: [.alert, .sound]) { granted, error in
    if let error = error {
        FileHandle.standardError.write(Data("authorization error: \(error.localizedDescription)\n".utf8))
        exitCode = 2
        semaphore.signal()
        return
    }
    guard granted else {
        FileHandle.standardError.write(Data("notification permission denied\n".utf8))
        exitCode = 3
        semaphore.signal()
        return
    }

    let content = UNMutableNotificationContent()
    content.title = bounded(args.title, max: 80, fallback: "Descartes alert")
    content.body = bounded(args.body, max: 240, fallback: "Descartes noticed a local system alert.")
    content.subtitle = "Descartes \(bounded(args.severity, max: 16, fallback: "info"))"
    content.categoryIdentifier = "DESCARTES_ALERT"
    content.userInfo = [
        "alert_id": bounded(args.alertId, max: 128, fallback: ""),
        "rule_id": bounded(args.ruleId, max: 128, fallback: ""),
        "severity": bounded(args.severity, max: 16, fallback: "info"),
    ]

    let request = UNNotificationRequest(identifier: "descartes-\(UUID().uuidString)", content: content, trigger: nil)
    center.add(request) { error in
        if let error = error {
            FileHandle.standardError.write(Data("delivery error: \(error.localizedDescription)\n".utf8))
            exitCode = 4
        }
        semaphore.signal()
    }
}

_ = semaphore.wait(timeout: .now() + 10)
exit(exitCode)
