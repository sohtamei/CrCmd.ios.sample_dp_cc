import Foundation
import Network

final class PTPIPConnection {
    var onLog: ((String) -> Void)?
    var onEvent: ((Data) -> Void)?

    private enum PacketType: UInt32 {
        case initCommandRequest = 1
        case initCommandAck = 2
        case initEventRequest = 3
        case initEventAck = 4
        case initFail = 5
        case operationRequest = 6
        case operationResponse = 7
        case event = 8
        case startData = 9
        case data = 10
        case cancel = 11
        case endData = 12
    }

    private struct PendingOperation {
        let transactionID: UInt32
        let completion: (Bool, Data?) -> Void
        var inData = Data()
    }

    private struct QueuedOperation {
        let opCode: UInt16
        let params: [UInt32]
        let outData: Data?
        let completion: (Bool, Data?) -> Void
    }

    private let host: String
    private let port: UInt16
    private let queue = DispatchQueue(label: "PTPIPConnection.queue")

    private var commandConnection: NWConnection?
    private var eventConnection: NWConnection?
    private var commandBuffer = Data()
    private var eventBuffer = Data()
    private var connectCompletion: ((Bool) -> Void)?
    private var connectionNumber: UInt32 = 0
    private var nextTransactionID: UInt32 = 1
    private var pendingOperation: PendingOperation?
    private var operationQueue: [QueuedOperation] = []
    private var operationTimeout: DispatchWorkItem?

    init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    func connect(completion: @escaping (Bool) -> Void) {
        queue.async {
            self.connectCompletion = completion
            self.openCommandConnection()
        }
    }

    func disconnect() {
        queue.async {
            guard self.commandConnection != nil, self.pendingOperation == nil else {
                self.cancelConnections()
                return
            }

            self.sendCommand(opCode: PTP_OC.CloseSession, params: [], outData: nil) { [self] _, _ in
                self.cancelConnections()
            }
        }
    }

    func sendOperation(opCode: UInt16, params: [UInt32], outData: Data?, completion: @escaping (Bool, Data?) -> Void) {
        queue.async {
            let operation = QueuedOperation(opCode: opCode, params: params, outData: outData, completion: completion)

            guard self.pendingOperation == nil else {
                self.operationQueue.append(operation)
                return
            }

            self.startOperation(operation)
        }
    }

    private func sendCommand(opCode: PTP_OC, params: [UInt32], outData: Data?, completion: @escaping (Bool, Data?) -> Void) {
        sendOperation(opCode: opCode.rawValue, params: params, outData: outData, completion: completion)
    }

    private func openCommandConnection() {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            connectCompletion?(false)
            connectCompletion = nil
            return
        }

        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
        commandConnection = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            self.queue.async {
                switch state {
                case .ready:
                    self.log("PTP-IP command channel ready")
                    self.receiveCommand()
                    let data = self.makeInitCommandRequest()
                    //self.log("1:\(data.hexDump())")
                    connection.send(content: data, completion: .contentProcessed { [weak self] error in
                        if let error {
                            self?.failConnect("PTP-IP init command failed: \(error.localizedDescription)")
                        }
                    })
                case .failed(let error):
                    self.failConnect("PTP-IP command channel failed: \(error.localizedDescription)")
                default:
                    break
                }
            }
        }
        connection.start(queue: queue)
    }

    private func openEventConnection() {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            failConnect("PTP-IP invalid port")
            return
        }

        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
        eventConnection = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            self.queue.async {
                switch state {
                case .ready:
                    self.log("PTP-IP event channel ready")
                    self.receiveEvent()
                    let data = self.makeInitEventRequest()
                    //self.log("3:\(data.hexDump())")
                    connection.send(content: data, completion: .contentProcessed { [weak self] error in
                        if let error {
                            self?.failConnect("PTP-IP init event failed: \(error.localizedDescription)")
                        }
                    })
                case .failed(let error):
                    self.failConnect("PTP-IP event channel failed: \(error.localizedDescription)")
                default:
                    break
                }
            }
        }
        connection.start(queue: queue)
    }

    private func receiveCommand() {
        commandConnection?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            self.queue.async {
                if let data {
                    //self.log("r:\(data.hexDump())")
                    self.commandBuffer.append(data)
                    self.drainCommandPackets()
                }

                if let error {
                    self.finishOperation(false, nil, "PTP-IP command receive failed: \(error.localizedDescription)")
                    return
                }

                if isComplete {
                    self.finishOperation(false, nil, "PTP-IP command channel closed")
                    return
                }

                self.receiveCommand()
            }
        }
    }

    private func receiveEvent() {
        eventConnection?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            self.queue.async {
                if let data {
                    //self.log("e:\(data.hexDump())")
                    self.eventBuffer.append(data)
                    self.drainEventPackets()
                }

                if let error {
                    self.log("PTP-IP event receive failed: \(error.localizedDescription)")
                    return
                }

                if isComplete {
                    self.log("PTP-IP event channel closed")
                    return
                }

                self.receiveEvent()
            }
        }
    }

    private func drainCommandPackets() {
        while let packet = popPacket(from: &commandBuffer) {
            handleCommandPacket(packet)
        }
    }

    private func drainEventPackets() {
        while let packet = popPacket(from: &eventBuffer) {
            handleEventPacket(packet)
        }
    }

    private func popPacket(from buffer: inout Data) -> Data? {
        guard buffer.count >= 8 else { return nil }
        let length = Int(PTPParser.readUInt32LE(buffer, offset: 0))
        guard length >= 8 else {
            buffer.removeAll()
            return nil
        }
        guard buffer.count >= length else { return nil }
        let packet = buffer.subdata(in: 0..<length)
        buffer.removeSubrange(0..<length)
        return packet
    }

    private func handleCommandPacket(_ packet: Data) {
        let rawType = PTPParser.readUInt32LE(packet, offset: 4)
        guard let packetType = PacketType(rawValue: rawType) else {
            log("PTP-IP unknown packet type: \(rawType)")
            return
        }

        switch packetType {
        case .initCommandAck:
            guard packet.count >= 12 else {
                failConnect("PTP-IP init command ack too short")
                return
            }
            connectionNumber = PTPParser.readUInt32LE(packet, offset: 8)
            log("PTP-IP connection number: \(connectionNumber)")
            openEventConnection()

        case .initFail:
            failConnect("PTP-IP init failed")

        case .startData:
            if var pendingOperation = pendingOperation {
                pendingOperation.inData.removeAll()
                self.pendingOperation = pendingOperation
            }

        case .data:
            guard packet.count >= 12 else { return }
            if var pendingOperation = pendingOperation {
                pendingOperation.inData.append(packet.subdata(in: 12..<packet.count))
                self.pendingOperation = pendingOperation
            }

        case .endData:
            guard packet.count >= 12 else { return }
            if var pendingOperation = pendingOperation {
                pendingOperation.inData.append(packet.subdata(in: 12..<packet.count))
                self.pendingOperation = pendingOperation
            }

        case .operationResponse:
            handleOperationResponse(packet)

        default:
            break
        }
    }

    private func handleEventPacket(_ packet: Data) {
        let rawType = PTPParser.readUInt32LE(packet, offset: 4)
        guard let packetType = PacketType(rawValue: rawType) else { return }

        switch packetType {
        case .initEventAck:
            log("PTP-IP event channel initialized")
            self.sendCommand(opCode: PTP_OC.OpenSession, params: [1], outData: nil) { [weak self] result, _ in
                guard let self else { return }

                if result {
                    let completion = self.connectCompletion
                    self.connectCompletion = nil
                    self.log("PTP-IP PTP session opened")
                    completion?(true)
                } else {
                    self.failConnect("PTP-IP OpenSession failed")
                }
            }

        case .event:
            guard packet.count >= 14 else { return }
            onEvent?(makePTPEventContainer(from: packet))

        case .initFail:
            failConnect("PTP-IP event init failed")

        default:
            break
        }
    }

    private func handleOperationResponse(_ packet: Data) {
        guard packet.count >= 14 else {
            finishOperation(false, nil, "PTP-IP operation response too short")
            return
        }

        let responseCode = PTPParser.readUInt16LE(packet, offset: 8)
        let transactionID = PTPParser.readUInt32LE(packet, offset: 10)

        guard let pendingOperation, pendingOperation.transactionID == transactionID else {
            log("PTP-IP response for unexpected transaction: \(transactionID)")
            return
        }

        let data = pendingOperation.inData.isEmpty ? nil : pendingOperation.inData
        finishOperation(responseCode == 0x2001, data, nil)
    }

    private func finishOperation(_ result: Bool, _ inData: Data?, _ logLine: String?) {
        if let logLine {
            log(logLine)
        }
        operationTimeout?.cancel()
        operationTimeout = nil
        let completion = pendingOperation?.completion
        pendingOperation = nil
        completion?(result, inData)
        startNextOperation()
    }

    private func scheduleOperationTimeout(transactionID: UInt32) {
        operationTimeout?.cancel()
        let timeout = DispatchWorkItem { [weak self] in
            guard let self else { return }
            guard self.pendingOperation?.transactionID == transactionID else { return }
            self.finishOperation(false, nil, "PTP-IP operation timeout")
        }
        operationTimeout = timeout
        queue.asyncAfter(deadline: .now() + 5.0, execute: timeout)
    }

    private func cancelConnections() {
        commandConnection?.cancel()
        eventConnection?.cancel()
        commandConnection = nil
        eventConnection = nil
        operationTimeout?.cancel()
        operationTimeout = nil
        pendingOperation = nil
        let queuedOperations = operationQueue
        operationQueue.removeAll()
        queuedOperations.forEach { $0.completion(false, nil) }
    }

    private func startOperation(_ operation: QueuedOperation) {
        guard let commandConnection = commandConnection else {
            log("PTP-IP command connection is closed")
            operation.completion(false, nil)
            startNextOperation()
            return
        }

        let transactionID = nextTransactionID
        nextTransactionID += 1
        pendingOperation = PendingOperation(transactionID: transactionID, completion: operation.completion)
        scheduleOperationTimeout(transactionID: transactionID)

        let request = makeOperationRequest(
            opCode: operation.opCode,
            transactionID: transactionID,
            params: operation.params,
            hasOutData: operation.outData != nil
        )
        //log("6:\(request.hexDump())")
        commandConnection.send(content: request, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if let error {
                self.finishOperation(false, nil, "PTP-IP send operation failed: \(error.localizedDescription)")
                return
            }

            guard let outData = operation.outData else { return }
            self.sendOutData(outData, transactionID: transactionID)
        })
    }

    private func startNextOperation() {
        guard commandConnection != nil, pendingOperation == nil, !operationQueue.isEmpty else { return }

        let operation = operationQueue.removeFirst()
        startOperation(operation)
    }

    private func failConnect(_ message: String) {
        log(message)
        cancelConnections()
        let completion = connectCompletion
        connectCompletion = nil
        completion?(false)
    }

    private func sendOutData(_ outData: Data, transactionID: UInt32) {
        guard let commandConnection else { return }

        var start = Data()
        appendUInt32LE(20, to: &start)
        appendUInt32LE(PacketType.startData.rawValue, to: &start)
        appendUInt32LE(transactionID, to: &start)
        appendUInt64LE(UInt64(outData.count), to: &start)

        var end = Data()
        appendUInt32LE(UInt32(12 + outData.count), to: &end)
        appendUInt32LE(PacketType.endData.rawValue, to: &end)
        appendUInt32LE(transactionID, to: &end)
        end.append(outData)

        //log("9:\(start.hexDump())")
        commandConnection.send(content: start, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if let error {
                self.finishOperation(false, nil, "PTP-IP start data failed: \(error.localizedDescription)")
                return
            }

            //log("c:\(end.hexDump())")
            commandConnection.send(content: end, completion: .contentProcessed { [weak self] error in
                if let error {
                    self?.finishOperation(false, nil, "PTP-IP end data failed: \(error.localizedDescription)")
                }
            })
        })
    }

    private func makeInitCommandRequest() -> Data {
        let name = "CrCmd.DPCC"
        let nameBytes = utf16NullTerminated(name)
        var data = Data()
        appendUInt32LE(UInt32(8 + 16 + nameBytes.count + 4), to: &data)
        appendUInt32LE(PacketType.initCommandRequest.rawValue, to: &data)
        var uuid = UUID().uuid
        withUnsafeBytes(of: &uuid) { data.append(contentsOf: $0) }
        data.append(nameBytes)
        appendUInt32LE(0x00010000, to: &data)
        return data
    }

    private func makeInitEventRequest() -> Data {
        var data = Data()
        appendUInt32LE(12, to: &data)
        appendUInt32LE(PacketType.initEventRequest.rawValue, to: &data)
        appendUInt32LE(connectionNumber, to: &data)
        return data
    }

    private func makeOperationRequest(opCode: UInt16, transactionID: UInt32, params: [UInt32], hasOutData: Bool) -> Data {
        var data = Data()
        appendUInt32LE(UInt32(18 + params.count * 4), to: &data)
        appendUInt32LE(PacketType.operationRequest.rawValue, to: &data)
        appendUInt32LE(hasOutData ? 2 : 1, to: &data)
        appendUInt16LE(opCode, to: &data)
        appendUInt32LE(transactionID, to: &data)
        for param in params {
            appendUInt32LE(param, to: &data)
        }
        return data
    }

    private func makePTPEventContainer(from packet: Data) -> Data {
        let eventCode = PTPParser.readUInt16LE(packet, offset: 8)
        let transactionID = PTPParser.readUInt32LE(packet, offset: 10)
        let paramBytes = max(0, packet.count - 14)

        var data = Data()
        appendUInt32LE(UInt32(12 + paramBytes), to: &data)
        appendUInt16LE(PTPContainerType.event.rawValue, to: &data)
        appendUInt16LE(eventCode, to: &data)
        appendUInt32LE(transactionID, to: &data)
        if paramBytes > 0 {
            data.append(packet.subdata(in: 14..<packet.count))
        }
        return data
    }

    private func utf16NullTerminated(_ text: String) -> Data {
        var data = Data()
        for codeUnit in text.utf16 {
            appendUInt16LE(codeUnit, to: &data)
        }
        appendUInt16LE(0, to: &data)
        return data
    }

    private func appendUInt16LE(_ value: UInt16, to data: inout Data) {
        var value = value.littleEndian
        withUnsafeBytes(of: &value) { data.append(contentsOf: $0) }
    }

    private func appendUInt32LE(_ value: UInt32, to data: inout Data) {
        var value = value.littleEndian
        withUnsafeBytes(of: &value) { data.append(contentsOf: $0) }
    }

    private func appendUInt64LE(_ value: UInt64, to data: inout Data) {
        var value = value.littleEndian
        withUnsafeBytes(of: &value) { data.append(contentsOf: $0) }
    }

    private func log(_ text: String) {
        onLog?(text)
    }
}
