#ifndef W5100_HH
#define W5100_HH

#include "MSXDevice.hh"
#include "Socket.hh"

#include <array>
#include <chrono>
#include <deque>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace openmsx {

class W5100
{
public:
	struct Socket final {
		byte mode = 0;
		byte command = 0;
		byte interrupt = 0;
		byte status = 0;
		uint16_t txWritePointer = 0;
		uint16_t rxReadPointer = 0;
	};

private:
	enum class DhcpHandling : byte {
		NOT_DHCP,
		HANDLED,
		BLOCKED,
	};

	enum class DnsHandling : byte {
		NOT_DNS,
		HANDLED,
		FAILED,
	};

	struct PendingUdpDatagram final {
		uint16_t totalSize = 0;
		uint16_t payloadSize = 0;
		uint16_t remainingSize = 0;
	};

	struct RuntimeSocket final {
		SOCKET fd = OPENMSX_INVALID_SOCKET;
		bool connecting = false;
		bool listening = false;
		bool peerClosed = false;
		std::chrono::steady_clock::time_point connectDeadline = {};
		uint16_t txReadPointer = 0;
		uint16_t txSendPointer = 0;
		uint16_t rxQueued = 0;
		uint16_t rxWriteOffset = 0;
		uint16_t lastRxReadPointer = 0;
		std::vector<byte> pendingTx;
		std::deque<PendingUdpDatagram> pendingUdp;
		sockaddr_in remoteAddr = {};
	};

public:
	static constexpr uint16_t SEGMENT_SIZE = 0x4000;
	static constexpr uint16_t TOTAL_SIZE = 2 * SEGMENT_SIZE;

	W5100();
	~W5100();

	void reset();

	[[nodiscard]] byte readMem(bool segment1, uint16_t offset);
	[[nodiscard]] byte peekMem(bool segment1, uint16_t offset) const;
	void writeMem(bool segment1, uint16_t offset, byte value);

	template<typename Archive>
	void serialize(Archive& ar, unsigned version);

	static constexpr uint16_t COMMON_REGISTER_SEGMENT = 0x0000;
	static constexpr uint16_t BUFFER_SEGMENT = 0x4000;
	static constexpr uint16_t SOCKET_BASE = 0x0400;
	static constexpr uint16_t SOCKET_SIZE = 0x0100;
	static constexpr uint16_t SOCKET_COUNT = 4;

	static constexpr uint16_t REG_MR = 0x0000;
	static constexpr uint16_t REG_IR = 0x0015;
	static constexpr uint16_t REG_IMR = 0x0016;
	static constexpr uint16_t REG_RMSR = 0x001A;
	static constexpr uint16_t REG_TMSR = 0x001B;

	static constexpr byte RMSR_DEFAULT = 0x55; // 2kB RX per socket
	static constexpr byte TMSR_DEFAULT = 0x00; // 1kB TX per socket

	static constexpr uint16_t SN_MR = 0x00;
	static constexpr uint16_t SN_CR = 0x01;
	static constexpr uint16_t SN_IR = 0x02;
	static constexpr uint16_t SN_SR = 0x03;
	static constexpr uint16_t SN_PORT0 = 0x04;
	static constexpr uint16_t SN_PORT1 = 0x05;
	static constexpr uint16_t SN_DIPR0 = 0x0C;
	static constexpr uint16_t SN_DPORT0 = 0x10;
	static constexpr uint16_t SN_TOS = 0x15;
	static constexpr uint16_t SN_TTL = 0x16;
	static constexpr uint16_t SN_TX_FSR0 = 0x20;
	static constexpr uint16_t SN_TX_FSR1 = 0x21;
	static constexpr uint16_t SN_TX_RD0 = 0x22;
	static constexpr uint16_t SN_TX_RD1 = 0x23;
	static constexpr uint16_t SN_TX_WR0 = 0x24;
	static constexpr uint16_t SN_TX_WR1 = 0x25;
	static constexpr uint16_t SN_RX_RSR0 = 0x26;
	static constexpr uint16_t SN_RX_RSR1 = 0x27;
	static constexpr uint16_t SN_RX_RD0 = 0x28;
	static constexpr uint16_t SN_RX_RD1 = 0x29;

	static constexpr byte COMMAND_OPEN = 0x01;
	static constexpr byte COMMAND_LISTEN = 0x02;
	static constexpr byte COMMAND_CONNECT = 0x04;
	static constexpr byte COMMAND_DISCON = 0x08;
	static constexpr byte COMMAND_CLOSE = 0x10;
	static constexpr byte COMMAND_SEND = 0x20;
	static constexpr byte COMMAND_RECV = 0x40;

	static constexpr byte SOCKET_MODE_TCP = 0x01;
	static constexpr byte SOCKET_MODE_UDP = 0x02;
	static constexpr byte SOCKET_MODE_IPRAW = 0x03;

	static constexpr byte SOCKET_STATUS_CLOSED = 0x00;
	static constexpr byte SOCKET_STATUS_INIT = 0x13;
	static constexpr byte SOCKET_STATUS_LISTEN = 0x14;
	static constexpr byte SOCKET_STATUS_SYNSENT = 0x15;
	static constexpr byte SOCKET_STATUS_ESTABLISHED = 0x17;
	static constexpr byte SOCKET_STATUS_CLOSE_WAIT = 0x1C;
	static constexpr byte SOCKET_STATUS_UDP = 0x22;
	static constexpr byte SOCKET_STATUS_IPRAW = 0x32;

	static constexpr byte SN_IR_CON = 0x01;
	static constexpr byte SN_IR_DISCON = 0x02;
	static constexpr byte SN_IR_RECV = 0x04;
	static constexpr byte SN_IR_TIMEOUT = 0x08;
	static constexpr byte SN_IR_SEND_OK = 0x10;

	static constexpr uint16_t TX_BUFFER_SIZE = 0x0400;
	static constexpr uint16_t RX_BUFFER_SIZE = 0x0800;
	static constexpr uint16_t TX_BUFFER_BASE = BUFFER_SEGMENT + 0x0000;
	static constexpr uint16_t RX_BUFFER_BASE = BUFFER_SEGMENT + 0x2000;
	static constexpr auto CONNECT_TIMEOUT = std::chrono::seconds(3);

	[[nodiscard]] static constexpr uint16_t segmentBase(bool segment1)
	{
		return segment1 ? BUFFER_SEGMENT : COMMON_REGISTER_SEGMENT;
	}

	[[nodiscard]] uint16_t absoluteAddress(bool segment1, uint16_t offset) const;
	[[nodiscard]] static bool isWritableRegister(uint16_t address);
	[[nodiscard]] static uint16_t socketBase(unsigned socket);
	[[nodiscard]] static unsigned getSocketIndex(uint16_t address);
	[[nodiscard]] static uint16_t getSocketRegister(uint16_t address);
	[[nodiscard]] static uint16_t getTxBase(unsigned socket);
	[[nodiscard]] static uint16_t getRxBase(unsigned socket);
	[[nodiscard]] byte getSocketMode(unsigned socket) const;
	[[nodiscard]] uint16_t readReg16(unsigned socket, uint16_t reg) const;
	[[nodiscard]] uint16_t readCommon16(uint16_t reg) const;
	void writeReg16(unsigned socket, uint16_t reg, uint16_t value);
	void writeCommon16(uint16_t reg, uint16_t value);
	void initializeSocketRegisters(unsigned socket);
	void resetState(bool preserveBufferMemory);
	void processNetwork();
	void processSocket(unsigned socket);
	void handleCommand(unsigned socket, byte command);
	void handleOpen(unsigned socket);
	void handleListen(unsigned socket);
	void handleConnect(unsigned socket);
	void handleDisconnect(unsigned socket);
	void handleClose(unsigned socket);
	void handleSend(unsigned socket);
	void handleReceive(unsigned socket);
	void updateSocketStatus(unsigned socket, byte status);
	void updateSocketInterrupt(unsigned socket, byte value);
	void updateCommonInterrupt();
	void updateTxFreeSpace(unsigned socket);
	void updateRxReceivedSize(unsigned socket);
	void updatePointerMirrors(unsigned socket);
	void resetSocketTransferState(unsigned socket);
	void closeHostSocket(unsigned socket);
	void closeRuntimeSocket(unsigned socket);
	void closeAllRuntimeSockets();
	bool openTcpSocket(unsigned socket);
	bool openTcpListenSocket(unsigned socket);
	bool openUdpSocket(unsigned socket);
	void pollConnecting(unsigned socket);
	void pollListening(unsigned socket);
	void pollTcpReceive(unsigned socket);
	void pollUdpReceive(unsigned socket);
	void pollTcpSend(unsigned socket);
	[[nodiscard]] DhcpHandling maybeHandleDhcp(unsigned socket, std::span<const byte> payload);
	[[nodiscard]] DnsHandling maybeHandleDns(unsigned socket, std::span<const byte> payload);
	void queueReceivedTcpData(unsigned socket, const byte* data, size_t size);
	[[nodiscard]] bool queueReceivedUdpData(unsigned socket, const sockaddr_in& addr, const byte* data, size_t size);
	[[nodiscard]] bool hasRxSpace(unsigned socket, uint16_t required) const;
	[[nodiscard]] bool isGuestUdpPortInUse(unsigned socket, uint16_t port) const;
	void writeRxBytes(unsigned socket, std::span<const byte> data);
	[[nodiscard]] std::vector<byte> extractTxBytes(unsigned socket, uint16_t length) const;
	[[nodiscard]] sockaddr_in getDestinationAddress(unsigned socket) const;
	[[nodiscard]] uint16_t getLocalPort(unsigned socket) const;
	[[nodiscard]] SOCKET createSocket(int type, int protocol) const;
	static void setNonBlocking(SOCKET fd);

private:
	[[no_unique_address]] SocketActivator socketActivator;
	std::array<byte, TOTAL_SIZE> memory = {};
	std::array<Socket, SOCKET_COUNT> sockets = {};
	std::array<RuntimeSocket, SOCKET_COUNT> runtime = {};
	uint32_t lastResolvedIp = 0;
};

} // namespace openmsx

#endif
