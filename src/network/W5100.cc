#include "W5100.hh"

#include "serialize.hh"
#include "strCat.hh"

#include <algorithm>
#include <bit>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <span>
#include <string>
#include <vector>

#ifndef _WIN32
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <net/route.h>
#include <sys/socket.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#endif
#include <sys/select.h>
#endif

namespace openmsx {

// Enable W5100 debug tracing by switching the '#if 1' below to '#if 0'.
// When disabled, printDebug() is a no-op template that the compiler
// eliminates entirely — no runtime cost and no file/stderr I/O.
#if 1
template<typename... Args>
static void printDebug(Args&&...)
{
	// nothing
}
#else
template<typename... Args>
static void printDebug(Args&&... args)
{
	std::cerr << strCat(std::forward<Args>(args)...) << '\n';
}
#endif

namespace {

[[nodiscard]] static bool socketWouldBlock()
{
#ifdef _WIN32
	return WSAGetLastError() == WSAEWOULDBLOCK;
#else
	return errno == EWOULDBLOCK || errno == EAGAIN;
#endif
}

#ifdef _WIN32
using SystemSockLen = int;
#else
using SystemSockLen = ::socklen_t;
#endif

struct HostNetworkConfig final {
	uint32_t localIp = 0;
	uint32_t subnetMask = 0;
	uint32_t gateway = 0;
	std::array<uint32_t, 2> dnsServers = {};
	uint32_t serverId = 0;
};

[[nodiscard]] static constexpr uint32_t bytesToIp(byte a, byte b, byte c, byte d)
{
	return (uint32_t(a) << 24) | (uint32_t(b) << 16) | (uint32_t(c) << 8) | uint32_t(d);
}

static void appendIp(std::vector<byte>& out, uint32_t ip)
{
	out.push_back(byte((ip >> 24) & 0xFF));
	out.push_back(byte((ip >> 16) & 0xFF));
	out.push_back(byte((ip >> 8) & 0xFF));
	out.push_back(byte(ip & 0xFF));
}

[[nodiscard]] static bool isUsableIpv4(uint32_t ip)
{
	return (ip != 0) && ((ip >> 24) != 127);
}

#ifndef _WIN32
[[nodiscard]] static std::optional<uint32_t> probeOutboundIpv4()
{
	constexpr std::array<uint32_t, 2> probes = {
		bytesToIp(8, 8, 8, 8),
		bytesToIp(1, 1, 1, 1)
	};

	for (auto probeIp : probes) {
		auto fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (fd == OPENMSX_INVALID_SOCKET) return {};

		sockaddr_in remote{};
		remote.sin_family = AF_INET;
		remote.sin_port = htons(53);
		remote.sin_addr.s_addr = htonl(probeIp);

		auto connected = connect(fd, reinterpret_cast<const sockaddr*>(&remote), sizeof(remote));
		if (connected == 0) {
			sockaddr_in local{};
			SystemSockLen len = sizeof(local);
			if (getsockname(fd, reinterpret_cast<sockaddr*>(&local), &len) == 0) {
				sock_close(fd);
				auto ip = ntohl(local.sin_addr.s_addr);
				if (isUsableIpv4(ip)) return ip;
			}
		}
		sock_close(fd);
	}
	return {};
}

[[nodiscard]] static uint32_t findSubnetMask(uint32_t localIp)
{
	ifaddrs* ifaList = nullptr;
	if (getifaddrs(&ifaList) != 0) return 0;

	uint32_t result = 0;
	for (auto* ifa = ifaList; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr || !ifa->ifa_netmask) continue;
		if (ifa->ifa_addr->sa_family != AF_INET) continue;
		if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) continue;

		auto* addr = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
		auto* mask = reinterpret_cast<sockaddr_in*>(ifa->ifa_netmask);
		if (ntohl(addr->sin_addr.s_addr) != localIp) continue;

		result = ntohl(mask->sin_addr.s_addr);
		break;
	}

	freeifaddrs(ifaList);
	return result;
}

[[nodiscard]] static std::array<uint32_t, 2> readDnsServers()
{
	std::array<uint32_t, 2> result = {};
	std::ifstream input("/etc/resolv.conf");
	if (!input) return result;

	std::string line;
	size_t index = 0;
	while ((index < result.size()) && std::getline(input, line)) {
		constexpr std::string_view prefix = "nameserver";
		if (!line.starts_with(prefix)) continue;

		auto address = line.substr(prefix.size());
		auto begin = address.find_first_not_of(" \t");
		if (begin == std::string::npos) continue;
		auto end = address.find_first_of(" \t#", begin);
		auto token = address.substr(begin, end - begin);

		in_addr ipv4{};
		if (inet_pton(AF_INET, token.c_str(), &ipv4) != 1) continue;
		auto parsed = ntohl(ipv4.s_addr);
		if ((parsed == 0) || ((parsed & 0xFF000000u) == 0x7F000000u)) continue;
		result[index++] = parsed;
	}
	return result;
}

#ifdef __APPLE__
[[nodiscard]] static size_t sockaddrStorageSize(const sockaddr* sa)
{
	if (sa->sa_len == 0) return sizeof(long);
	auto mask = sizeof(long) - 1;
	return size_t((sa->sa_len + mask) & ~mask);
}

[[nodiscard]] static std::optional<uint32_t> queryDefaultGateway()
{
	int mib[] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_GATEWAY};
	size_t needed = 0;
	if (sysctl(mib, std::size(mib), nullptr, &needed, nullptr, 0) != 0) return {};

	std::vector<char> buffer(needed);
	if (sysctl(mib, std::size(mib), buffer.data(), &needed, nullptr, 0) != 0) return {};

	char* next = buffer.data();
	char* end = buffer.data() + needed;
	while (next < end) {
		auto* rtm = reinterpret_cast<rt_msghdr*>(next);
		auto* sa = reinterpret_cast<sockaddr*>(rtm + 1);
		std::array<sockaddr*, RTAX_MAX> addrs = {};
		for (int i = 0; i < RTAX_MAX; ++i) {
			if ((rtm->rtm_addrs & (1 << i)) != 0) {
				addrs[i] = sa;
				sa = reinterpret_cast<sockaddr*>(reinterpret_cast<char*>(sa) + sockaddrStorageSize(sa));
			}
		}

		auto* dst = reinterpret_cast<sockaddr_in*>(addrs[RTAX_DST]);
		auto* gw = reinterpret_cast<sockaddr_in*>(addrs[RTAX_GATEWAY]);
		if (dst && gw && (dst->sin_family == AF_INET) && (gw->sin_family == AF_INET) &&
		    (dst->sin_addr.s_addr == 0)) {
			return ntohl(gw->sin_addr.s_addr);
		}
		next += rtm->rtm_msglen;
	}
	return {};
}
#else
[[nodiscard]] static std::optional<uint32_t> queryDefaultGateway()
{
	std::ifstream input("/proc/net/route");
	if (!input) return {};

	std::string line;
	std::getline(input, line); // header
	while (std::getline(input, line)) {
		std::istringstream row(line);
		std::string iface, destinationHex, gatewayHex;
		unsigned flags = 0;
		if (!(row >> iface >> destinationHex >> gatewayHex >> std::hex >> flags)) continue;
		if ((destinationHex != "00000000") || ((flags & 0x2) == 0)) continue;

		auto gateway = std::stoul(gatewayHex, nullptr, 16);
		return ((gateway & 0x000000FFu) << 24) |
		       ((gateway & 0x0000FF00u) << 8) |
		       ((gateway & 0x00FF0000u) >> 8) |
		       ((gateway & 0xFF000000u) >> 24);
	}
	return {};
}
#endif

[[nodiscard]] static uint32_t deriveGatewayFallback(uint32_t localIp, uint32_t subnetMask, uint32_t dns)
{
	if (dns && subnetMask && ((dns & subnetMask) == (localIp & subnetMask))) {
		return dns;
	}
	if (!subnetMask) return 0;

	auto candidate = (localIp & subnetMask) | 1u;
	return (candidate != localIp) ? candidate : 0;
}

[[nodiscard]] static std::optional<HostNetworkConfig> queryHostNetworkConfig()
{
#ifdef _WIN32
	return {};
#else
	auto localIp = probeOutboundIpv4();
	if (!localIp) return {};

	HostNetworkConfig config;
	config.localIp = *localIp;
	config.subnetMask = findSubnetMask(config.localIp);
	config.dnsServers = readDnsServers();
	config.gateway = queryDefaultGateway().value_or(0);
	if (!config.gateway) {
		config.gateway = deriveGatewayFallback(config.localIp, config.subnetMask, config.dnsServers[0]);
	}
	config.serverId = config.gateway ? config.gateway
	                                 : (config.localIp ? config.localIp : config.dnsServers[0]);
	return config.serverId ? std::optional{config} : std::nullopt;
#endif
}

[[nodiscard]] static std::optional<byte> parseDhcpMessageType(std::span<const byte> payload)
{
	if ((payload.size() < 240) ||
	    (payload[236] != 99) || (payload[237] != 130) ||
	    (payload[238] != 83) || (payload[239] != 99)) {
		return {};
	}

	size_t pos = 240;
	while (pos < payload.size()) {
		auto code = payload[pos++];
		if (code == 0) continue;
		if (code == 255) break;
		if (pos >= payload.size()) break;

		auto length = payload[pos++];
		if ((pos + length) > payload.size()) break;
		if ((code == 53) && (length >= 1)) return payload[pos];
		pos += length;
	}
	return {};
}

[[nodiscard]] static std::vector<byte> buildDhcpReply(
	const HostNetworkConfig& config, std::span<const byte> request, byte requestType, byte replyType)
{
	std::vector<byte> reply(240, 0);
	reply[0] = 2; // BOOTREPLY
	reply[1] = request[1];
	reply[2] = request[2];
	reply[3] = 0;
	std::copy_n(request.begin() + 4, 8, reply.begin() + 4);   // xid, secs, flags
	std::copy_n(request.begin() + 28, 16, reply.begin() + 28); // chaddr

	if (requestType != 8) {
		reply[16] = byte((config.localIp >> 24) & 0xFF);
		reply[17] = byte((config.localIp >> 16) & 0xFF);
		reply[18] = byte((config.localIp >> 8) & 0xFF);
		reply[19] = byte(config.localIp & 0xFF);
	}
	reply[20] = byte((config.serverId >> 24) & 0xFF);
	reply[21] = byte((config.serverId >> 16) & 0xFF);
	reply[22] = byte((config.serverId >> 8) & 0xFF);
	reply[23] = byte(config.serverId & 0xFF);
	reply[236] = 99;
	reply[237] = 130;
	reply[238] = 83;
	reply[239] = 99;

	auto appendOption = [&](byte code, std::span<const byte> value) {
		reply.push_back(code);
		reply.push_back(byte(value.size()));
		reply.insert(reply.end(), value.begin(), value.end());
	};
	auto appendOption32 = [&](byte code, uint32_t value) {
		std::array<byte, 4> bytes = {
			byte((value >> 24) & 0xFF), byte((value >> 16) & 0xFF),
			byte((value >> 8) & 0xFF), byte(value & 0xFF)
		};
		appendOption(code, bytes);
	};

	appendOption(53, std::array<byte, 1>{replyType});
	appendOption32(54, config.serverId);
	if (replyType == 5) {
		appendOption32(51, 86400);
		appendOption32(58, 43200);
		appendOption32(59, 75600);
	}
	if (config.subnetMask) appendOption32(1, config.subnetMask);
	if (config.gateway) appendOption32(3, config.gateway);
	if (config.dnsServers[0]) {
		std::vector<byte> dns;
		appendIp(dns, config.dnsServers[0]);
		if (config.dnsServers[1]) appendIp(dns, config.dnsServers[1]);
		appendOption(6, dns);
	}
	reply.push_back(255);
	return reply;
}
#endif

} // namespace

W5100::W5100()
{
	reset();
}

W5100::~W5100()
{
	closeAllRuntimeSockets();
}

void W5100::reset()
{
	resetState(false);
}

void W5100::resetState(bool preserveBufferMemory)
{
	closeAllRuntimeSockets();

	if (!preserveBufferMemory) {
		memory.fill(0);
	} else {
		std::fill(memory.begin(), memory.begin() + BUFFER_SEGMENT, byte{0});
	}
	memory[REG_RMSR] = RMSR_DEFAULT;
	memory[REG_TMSR] = TMSR_DEFAULT;

	for (unsigned socket = 0; socket < SOCKET_COUNT; ++socket) {
		sockets[socket] = {};
		runtime[socket] = {};
		initializeSocketRegisters(socket);
	}
	updateCommonInterrupt();
}

byte W5100::readMem(bool segment1, uint16_t offset)
{
	// Process network when reading socket status or RX size registers.
	// On real W5100 hardware, network I/O happens asynchronously.
	// Polling on every memory access is unnecessary and causes timing
	// issues with the DenYoNet BIOS's slot-switching code.
	auto address = absoluteAddress(segment1, offset);
	if (address >= SOCKET_BASE && address < (SOCKET_BASE + SOCKET_COUNT * SOCKET_SIZE)) {
		auto socket = getSocketIndex(address);
		auto reg = getSocketRegister(address);
		if (reg == SN_SR || reg == SN_IR || reg == SN_RX_RSR0 ||
		    reg == SN_RX_RSR1 || reg == SN_TX_FSR0 || reg == SN_TX_FSR1) {
			processNetwork();
		}
		(void)socket;
	}
	auto value = peekMem(segment1, offset);
	return value;
}

byte W5100::peekMem(bool segment1, uint16_t offset) const
{
	return memory[absoluteAddress(segment1, offset)];
}

void W5100::writeMem(bool segment1, uint16_t offset, byte value)
{

	auto address = absoluteAddress(segment1, offset);
	if (!isWritableRegister(address)) {
		return;
	}

	if (address == REG_MR) {
		if (value & 0x80) {
			resetState(true);
			return;
		}
		memory[address] = value;
		return;
	}
	if (address == REG_RMSR) {
		memory[address] = RMSR_DEFAULT;
		return;
	}
	if (address == REG_TMSR) {
		memory[address] = TMSR_DEFAULT;
		return;
	}

	if ((segmentBase(false) + SOCKET_BASE) <= address &&
	    address < (segmentBase(false) + SOCKET_BASE + SOCKET_COUNT * SOCKET_SIZE)) {
		auto socket = getSocketIndex(address);
		auto reg = getSocketRegister(address);
		switch (reg) {
		case SN_MR:
			sockets[socket].mode = value;
			memory[address] = value;
			break;
		case SN_CR:
			handleCommand(socket, value);
			break;
		case SN_IR:
			updateSocketInterrupt(socket, sockets[socket].interrupt & ~value);
			break;
		case SN_TX_WR0:
		case SN_TX_WR1:
		case SN_RX_RD0:
		case SN_RX_RD1:
			memory[address] = value;
			updatePointerMirrors(socket);
			break;
		default:
			memory[address] = value;
			break;
		}
		return;
	}

	memory[address] = value;
}

uint16_t W5100::absoluteAddress(bool segment1, uint16_t offset) const
{
	return segmentBase(segment1) + (offset & (SEGMENT_SIZE - 1));
}

bool W5100::isWritableRegister(uint16_t address)
{
	if (address >= BUFFER_SEGMENT) return true;
	if (address == REG_MR || address == REG_IMR || address == REG_RMSR || address == REG_TMSR) return true;
	if (address < SOCKET_BASE || address >= (SOCKET_BASE + SOCKET_COUNT * SOCKET_SIZE)) return true;

	auto reg = getSocketRegister(address);
	return reg != SN_SR && reg != SN_TX_FSR0 && reg != SN_TX_FSR1 &&
	       reg != SN_RX_RSR0 && reg != SN_RX_RSR1 && reg != SN_TX_RD0 &&
	       reg != SN_TX_RD1;
}

uint16_t W5100::socketBase(unsigned socket)
{
	return uint16_t(SOCKET_BASE + socket * SOCKET_SIZE);
}

unsigned W5100::getSocketIndex(uint16_t address)
{
	return (address - SOCKET_BASE) / SOCKET_SIZE;
}

uint16_t W5100::getSocketRegister(uint16_t address)
{
	return (address - SOCKET_BASE) % SOCKET_SIZE;
}

uint16_t W5100::getTxBase(unsigned socket)
{
	return uint16_t(TX_BUFFER_BASE + socket * TX_BUFFER_SIZE);
}

uint16_t W5100::getRxBase(unsigned socket)
{
	return uint16_t(RX_BUFFER_BASE + socket * RX_BUFFER_SIZE);
}

byte W5100::getSocketMode(unsigned socket) const
{
	return memory[socketBase(socket) + SN_MR] & 0x0F;
}

uint16_t W5100::readReg16(unsigned socket, uint16_t reg) const
{
	auto base = socketBase(socket);
	return uint16_t((memory[base + reg] << 8) | memory[base + reg + 1]);
}

uint16_t W5100::readCommon16(uint16_t reg) const
{
	return uint16_t((memory[reg] << 8) | memory[reg + 1]);
}

void W5100::writeReg16(unsigned socket, uint16_t reg, uint16_t value)
{
	auto base = socketBase(socket);
	memory[base + reg] = value >> 8;
	memory[base + reg + 1] = value & 0xFF;
}

void W5100::writeCommon16(uint16_t reg, uint16_t value)
{
	memory[reg] = value >> 8;
	memory[reg + 1] = value & 0xFF;
}

void W5100::initializeSocketRegisters(unsigned socket)
{
	auto base = socketBase(socket);
	updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
	updateSocketInterrupt(socket, 0);
	memory[base + SN_MR] = 0;
	memory[base + SN_CR] = 0;
	writeReg16(socket, SN_TX_RD0, 0);
	writeReg16(socket, SN_TX_WR0, 0);
	writeReg16(socket, SN_RX_RD0, 0);
	updateTxFreeSpace(socket);
	updateRxReceivedSize(socket);
	updatePointerMirrors(socket);
}

void W5100::resetSocketTransferState(unsigned socket)
{
	runtime[socket] = {};
	writeReg16(socket, SN_TX_RD0, 0);
	writeReg16(socket, SN_TX_WR0, 0);
	writeReg16(socket, SN_RX_RD0, 0);
	updateRxReceivedSize(socket);
	updateTxFreeSpace(socket);
	updatePointerMirrors(socket);
}

void W5100::processNetwork()
{
	for (unsigned socket = 0; socket < SOCKET_COUNT; ++socket) {
		processSocket(socket);
	}
}

void W5100::processSocket(unsigned socket)
{
	pollConnecting(socket);
	pollListening(socket);
	pollTcpSend(socket);

	switch (sockets[socket].status) {
	case SOCKET_STATUS_ESTABLISHED:
	case SOCKET_STATUS_CLOSE_WAIT:
		if (getSocketMode(socket) == SOCKET_MODE_TCP) {
			pollTcpReceive(socket);
		}
		break;
	case SOCKET_STATUS_UDP:
		pollUdpReceive(socket);
		break;
	default:
		break;
	}
}

void W5100::handleCommand(unsigned socket, byte command)
{
	processNetwork();

	auto& info = sockets[socket];
	auto base = socketBase(socket);

	info.command = command;
	{
		static const char* cmdNames[] = {"?","OPEN","LISTEN","?","CONNECT","?","?","?","DISCON","?","?","?","?","?","?","?","CLOSE","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","SEND","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","?","RECV"};
		auto cmdIdx = command < 65 ? command : 0;
		printDebug("[W5100] CMD socket=", socket,
		           " cmd=0x", hex_string<2>(command), "(", cmdNames[cmdIdx], ")",
		           " mode=0x", hex_string<2>(getSocketMode(socket)),
		           " status=0x", hex_string<2>(info.status));
	}
	switch (command) {
	case COMMAND_OPEN:    handleOpen(socket); break;
	case COMMAND_LISTEN:  handleListen(socket); break;
	case COMMAND_CONNECT: handleConnect(socket); break;
	case COMMAND_DISCON:  handleDisconnect(socket); break;
	case COMMAND_CLOSE:   handleClose(socket); break;
	case COMMAND_SEND:    handleSend(socket); break;
	case COMMAND_RECV:    handleReceive(socket); break;
	default: break;
	}

	memory[base + SN_CR] = 0;
	info.command = 0;
}

void W5100::handleOpen(unsigned socket)
{
	closeHostSocket(socket);
	resetSocketTransferState(socket);
	// Clear any stale interrupt bits from a previous session (DISCON,
	// TIMEOUT, etc.) so the guest sees a fresh socket. Matches the FUSE
	// reference implementation's w5100_socket_clean behaviour.
	updateSocketInterrupt(socket, 0);

	switch (getSocketMode(socket)) {
	case SOCKET_MODE_TCP:
		updateSocketStatus(socket, SOCKET_STATUS_INIT);
		break;
	case SOCKET_MODE_UDP:
		if (openUdpSocket(socket)) {
			updateSocketStatus(socket, SOCKET_STATUS_UDP);
		} else {
			updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
			updateSocketInterrupt(socket, SN_IR_TIMEOUT);
		}
		break;
	case SOCKET_MODE_IPRAW:
		updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
		updateSocketInterrupt(socket, SN_IR_TIMEOUT);
		break;
	default:
		updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
		break;
	}
}

void W5100::handleListen(unsigned socket)
{
	if (sockets[socket].status != SOCKET_STATUS_INIT) return;
	if (!openTcpListenSocket(socket)) {
		updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_TIMEOUT);
		updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
		return;
	}
	if (listen(runtime[socket].fd, 1) != 0) {
		updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_TIMEOUT);
		updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
		closeRuntimeSocket(socket);
		return;
	}
	runtime[socket].listening = true;
	updateSocketStatus(socket, SOCKET_STATUS_LISTEN);
}

void W5100::handleConnect(unsigned socket)
{
	if (sockets[socket].status != SOCKET_STATUS_INIT) return;

	auto addr = getDestinationAddress(socket);
	{
		auto ip = ntohl(addr.sin_addr.s_addr);
		auto port = ntohs(addr.sin_port);
		printDebug("[W5100] TCP CONNECT socket=", socket, " dst=",
		           (ip>>24)&0xFF, '.', (ip>>16)&0xFF, '.', (ip>>8)&0xFF, '.', ip&0xFF,
		           ':', port);
		// If the destination IP doesn't match the last DNS-resolved IP
		// and we have a recent DNS result, the BIOS likely returned a
		// corrupted IP due to the EXX/interrupt register corruption bug.
		// Substitute the correct IP from our DNS cache.
		if (lastResolvedIp != 0 && ip != lastResolvedIp && port == 80) {
			printDebug("[W5100] TCP CONNECT: IP mismatch with DNS cache, correcting to ",
			           (lastResolvedIp>>24)&0xFF, '.', (lastResolvedIp>>16)&0xFF, '.',
			           (lastResolvedIp>>8)&0xFF, '.', lastResolvedIp&0xFF);
			addr.sin_addr.s_addr = htonl(lastResolvedIp);
			// Also fix the W5100 socket registers so guest sees the correct IP
			auto base = socketBase(socket) + SN_DIPR0;
			memory[base + 0] = byte((lastResolvedIp >> 24) & 0xFF);
			memory[base + 1] = byte((lastResolvedIp >> 16) & 0xFF);
			memory[base + 2] = byte((lastResolvedIp >> 8) & 0xFF);
			memory[base + 3] = byte(lastResolvedIp & 0xFF);
		}
	}
	if ((addr.sin_addr.s_addr == 0) || (addr.sin_port == 0)) {
		updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_TIMEOUT);
		updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
		closeRuntimeSocket(socket);
		return;
	}

	if (!openTcpSocket(socket)) {
		printDebug("[W5100] TCP CONNECT socket=", socket, " openTcpSocket failed");
		updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_TIMEOUT);
		updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
		return;
	}

	if (connect(runtime[socket].fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0) {
		printDebug("[W5100] TCP CONNECT socket=", socket, " => ESTABLISHED (immediate)");
		runtime[socket].remoteAddr = addr;
		updateSocketStatus(socket, SOCKET_STATUS_ESTABLISHED);
		updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_CON);
		return;
	}
	if (socketWouldBlock()
#ifdef _WIN32
	    || WSAGetLastError() == WSAEINPROGRESS
#else
	    || errno == EINPROGRESS
#endif
	   ) {
		printDebug("[W5100] TCP CONNECT socket=", socket, " => SYNSENT (async, errno=", errno, ")");
		runtime[socket].connecting = true;
		runtime[socket].connectDeadline = std::chrono::steady_clock::now() + CONNECT_TIMEOUT;
		runtime[socket].remoteAddr = addr;
		updateSocketStatus(socket, SOCKET_STATUS_SYNSENT);
		return;
	}

	printDebug("[W5100] TCP CONNECT socket=", socket, " => CLOSED (connect failed errno=", errno, ")");
	updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_TIMEOUT);
	updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
	closeRuntimeSocket(socket);
}

void W5100::handleDisconnect(unsigned socket)
{
	if (runtime[socket].fd != OPENMSX_INVALID_SOCKET) {
		shutdown(runtime[socket].fd, 2);
	}
	closeRuntimeSocket(socket);
	updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
	updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_DISCON);
}

void W5100::handleClose(unsigned socket)
{
	closeRuntimeSocket(socket);
	updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
	updateSocketInterrupt(socket, 0);
}

void W5100::handleSend(unsigned socket)
{
	auto& rt = runtime[socket];
	auto mode = getSocketMode(socket);
	if (mode == SOCKET_MODE_UDP) {
		if (rt.fd == OPENMSX_INVALID_SOCKET) {
			updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_TIMEOUT);
			return;
		}
		auto txWrite = readReg16(socket, SN_TX_WR0);
		auto length = uint16_t(txWrite - rt.txSendPointer);
		auto payload = extractTxBytes(socket, length);
		auto dhcpHandling = maybeHandleDhcp(socket, payload);
		if (dhcpHandling == DhcpHandling::HANDLED) {
			rt.txSendPointer = txWrite;
			rt.txReadPointer = txWrite;
			updatePointerMirrors(socket);
			updateTxFreeSpace(socket);
			return;
		}
		if (dhcpHandling == DhcpHandling::BLOCKED) return;
		auto dnsHandling = maybeHandleDns(socket, payload);
		if (dnsHandling == DnsHandling::HANDLED) {
			rt.txSendPointer = txWrite;
			rt.txReadPointer = txWrite;
			updatePointerMirrors(socket);
			updateTxFreeSpace(socket);
			return;
		}
		auto addr = getDestinationAddress(socket);
		{
			auto ip = ntohl(addr.sin_addr.s_addr);
			auto port = ntohs(addr.sin_port);
			printDebug("[W5100] UDP SEND socket=", socket, " dst=",
			           (ip>>24)&0xFF, '.', (ip>>16)&0xFF, '.', (ip>>8)&0xFF, '.', ip&0xFF,
			           ':', port, " len=", payload.size());
			if (port == 53 && payload.size() >= 12) {
				printDebug("[W5100]   DNS query id=0x",
				           hex_string<2>(payload[0]), hex_string<2>(payload[1]),
				           " flags=0x",
				           hex_string<2>(payload[2]), hex_string<2>(payload[3]),
				           " qdcount=",
				           unsigned((unsigned(payload[4])<<8)|unsigned(payload[5])));
				// Build query name as a single string and print with one call
				std::string name;
				size_t pos = 12;
				while (pos < payload.size() && payload[pos] != 0) {
					auto labelLen = unsigned(payload[pos++]);
					for (unsigned j = 0; j < labelLen && pos < payload.size(); ++j) {
						name += char(payload[pos++]);
					}
					if (pos < payload.size() && payload[pos] != 0) name += '.';
				}
				printDebug("[W5100]   DNS query name: ", name);
			}
		}
		auto sent = sendto(rt.fd, reinterpret_cast<const char*>(payload.data()), int(payload.size()), 0,
		                   reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
		if (sent != int(payload.size())) {
			printDebug("[W5100] UDP SEND FAILED socket=", socket, " errno=", errno);
			updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_TIMEOUT);
		} else {
			printDebug("[W5100] UDP SEND OK socket=", socket, " sent=", int(sent));
			rt.txSendPointer = txWrite;
			rt.txReadPointer = txWrite;
			updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_SEND_OK);
		}
		updatePointerMirrors(socket);
		updateTxFreeSpace(socket);
		return;
	}

	if (mode != SOCKET_MODE_TCP || rt.fd == OPENMSX_INVALID_SOCKET ||
	    ((sockets[socket].status != SOCKET_STATUS_ESTABLISHED) &&
	     (sockets[socket].status != SOCKET_STATUS_CLOSE_WAIT))) {
		updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_TIMEOUT);
		return;
	}

	auto txWrite = readReg16(socket, SN_TX_WR0);
	auto length = uint16_t(txWrite - rt.txSendPointer);
	auto payload = extractTxBytes(socket, length);
	rt.txSendPointer = txWrite;
	rt.pendingTx.insert(rt.pendingTx.end(), payload.begin(), payload.end());
	updatePointerMirrors(socket);
	pollTcpSend(socket);
}

void W5100::handleReceive(unsigned socket)
{
	auto& rt = runtime[socket];
	auto current = readReg16(socket, SN_RX_RD0);
	auto consumed = uint16_t(current - rt.lastRxReadPointer);
	rt.lastRxReadPointer = current;
	rt.rxQueued = std::min<uint16_t>(rt.rxQueued, uint16_t(std::max<int>(0, int(rt.rxQueued) - int(consumed))));

	if (getSocketMode(socket) == SOCKET_MODE_UDP) {
		while (!rt.pendingUdp.empty() && (consumed != 0)) {
			auto& datagram = rt.pendingUdp.front();
			auto consumedNow = std::min(consumed, datagram.remainingSize);
			datagram.remainingSize = uint16_t(datagram.remainingSize - consumedNow);
			consumed = uint16_t(consumed - consumedNow);
			if (datagram.remainingSize == 0) {
				rt.pendingUdp.pop_front();
			}
		}
	}

	updateRxReceivedSize(socket);
	updateSocketInterrupt(socket, sockets[socket].interrupt & ~SN_IR_RECV);
}

void W5100::updateSocketStatus(unsigned socket, byte status)
{
	sockets[socket].status = status;
	memory[socketBase(socket) + SN_SR] = status;
}

void W5100::updateSocketInterrupt(unsigned socket, byte value)
{
	sockets[socket].interrupt = value;
	memory[socketBase(socket) + SN_IR] = value;
	updateCommonInterrupt();
}

void W5100::updateCommonInterrupt()
{
	byte value = 0;
	for (unsigned socket = 0; socket < SOCKET_COUNT; ++socket) {
		if (sockets[socket].interrupt) value |= byte(1u << socket);
	}
	memory[REG_IR] = value;
}

void W5100::updateTxFreeSpace(unsigned socket)
{
	auto txWrite = readReg16(socket, SN_TX_WR0);
	auto used = uint16_t(txWrite - runtime[socket].txReadPointer);
	auto free = uint16_t((used >= TX_BUFFER_SIZE) ? 0 : (TX_BUFFER_SIZE - used));
	writeReg16(socket, SN_TX_FSR0, free);
}

void W5100::updateRxReceivedSize(unsigned socket)
{
	writeReg16(socket, SN_RX_RSR0, runtime[socket].rxQueued);
}

void W5100::updatePointerMirrors(unsigned socket)
{
	sockets[socket].txWritePointer = readReg16(socket, SN_TX_WR0);
	sockets[socket].rxReadPointer = readReg16(socket, SN_RX_RD0);
	writeReg16(socket, SN_TX_RD0, runtime[socket].txReadPointer);
	updateRxReceivedSize(socket);
	updateTxFreeSpace(socket);
}

void W5100::closeHostSocket(unsigned socket)
{
	auto& rt = runtime[socket];
	if (rt.fd != OPENMSX_INVALID_SOCKET) {
		sock_close(rt.fd);
		rt.fd = OPENMSX_INVALID_SOCKET;
	}
	rt.connecting = false;
	rt.listening = false;
}

void W5100::closeRuntimeSocket(unsigned socket)
{
	closeHostSocket(socket);
	resetSocketTransferState(socket);
}

void W5100::closeAllRuntimeSockets()
{
	for (unsigned socket = 0; socket < SOCKET_COUNT; ++socket) {
		closeRuntimeSocket(socket);
	}
}

bool W5100::openTcpSocket(unsigned socket)
{
	// Outbound TCP connections don't bind to the guest-visible local port.
	// The guest's W5100 local port is a virtual label; binding the host socket
	// to it would fail with EADDRINUSE when the guest reuses the same port
	// for back-to-back connections (the previous connection's 4-tuple is still
	// in TIME_WAIT on the host). Let the OS pick an ephemeral source port.
	closeHostSocket(socket);
	auto fd = createSocket(SOCK_STREAM, IPPROTO_TCP);
	if (fd == OPENMSX_INVALID_SOCKET) return false;
	runtime[socket].fd = fd;
	return true;
}

bool W5100::openTcpListenSocket(unsigned socket)
{
	closeHostSocket(socket);
	auto fd = createSocket(SOCK_STREAM, IPPROTO_TCP);
	if (fd == OPENMSX_INVALID_SOCKET) return false;

	auto port = getLocalPort(socket);
	if (port != 0) {
		sockaddr_in local{};
		local.sin_family = AF_INET;
		local.sin_port = htons(port);
		local.sin_addr.s_addr = htonl(INADDR_ANY);
		if (bind(fd, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0) {
			sock_close(fd);
			return false;
		}
	}

	runtime[socket].fd = fd;
	return true;
}

bool W5100::openUdpSocket(unsigned socket)
{
	closeHostSocket(socket);
	auto fd = createSocket(SOCK_DGRAM, IPPROTO_UDP);
	if (fd == OPENMSX_INVALID_SOCKET) return false;

	auto port = getLocalPort(socket);
	if ((port != 0) && isGuestUdpPortInUse(socket, port)) {
		sock_close(fd);
		return false;
	}
	int enableBroadcast = 1;
	setsockopt(fd, SOL_SOCKET, SO_BROADCAST,
#ifdef _WIN32
	           reinterpret_cast<const char*>(&enableBroadcast),
#else
	           &enableBroadcast,
#endif
	           sizeof(enableBroadcast));

	sockaddr_in local{};
	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(fd, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0) {
		sock_close(fd);
		return false;
	}

	runtime[socket].fd = fd;
	return true;
}

void W5100::pollConnecting(unsigned socket)
{
	auto& rt = runtime[socket];
	if (!rt.connecting || rt.fd == OPENMSX_INVALID_SOCKET) return;
	if (std::chrono::steady_clock::now() >= rt.connectDeadline) {
		printDebug("[W5100] pollConnecting socket=", socket, " TIMEOUT");
		rt.connecting = false;
		updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_TIMEOUT);
		updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
		closeRuntimeSocket(socket);
		return;
	}

	fd_set writeSet;
	FD_ZERO(&writeSet);
	FD_SET(rt.fd, &writeSet);
	timeval tv{0, 0};
	auto result = select(rt.fd + 1, nullptr, &writeSet, nullptr, &tv);
	if (result <= 0 || !FD_ISSET(rt.fd, &writeSet)) return;

	int err = 0;
	SystemSockLen len = sizeof(err);
	getsockopt(rt.fd, SOL_SOCKET, SO_ERROR, std::bit_cast<char*>(&err), &len);
	rt.connecting = false;
	if (err == 0) {
		printDebug("[W5100] pollConnecting socket=", socket, " => ESTABLISHED");
		updateSocketStatus(socket, SOCKET_STATUS_ESTABLISHED);
		updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_CON);
	} else {
		printDebug("[W5100] pollConnecting socket=", socket, " => CLOSED (err=", err, ")");
		updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_TIMEOUT);
		updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
		closeRuntimeSocket(socket);
	}
}

void W5100::pollListening(unsigned socket)
{
	auto& rt = runtime[socket];
	if (!rt.listening || rt.fd == OPENMSX_INVALID_SOCKET) return;

	fd_set readSet;
	FD_ZERO(&readSet);
	FD_SET(rt.fd, &readSet);
	timeval tv{0, 0};
	auto result = select(rt.fd + 1, &readSet, nullptr, nullptr, &tv);
	if (result <= 0 || !FD_ISSET(rt.fd, &readSet)) return;

	sockaddr_in addr{};
	SystemSockLen addrLen = sizeof(addr);
	auto accepted = accept(rt.fd, reinterpret_cast<sockaddr*>(&addr), &addrLen);
	if (accepted == OPENMSX_INVALID_SOCKET) return;

	sock_close(rt.fd);
	rt.fd = accepted;
	setNonBlocking(rt.fd);
	rt.listening = false;
	rt.remoteAddr = addr;
	memory[socketBase(socket) + SN_DIPR0 + 0] = (ntohl(addr.sin_addr.s_addr) >> 24) & 0xFF;
	memory[socketBase(socket) + SN_DIPR0 + 1] = (ntohl(addr.sin_addr.s_addr) >> 16) & 0xFF;
	memory[socketBase(socket) + SN_DIPR0 + 2] = (ntohl(addr.sin_addr.s_addr) >> 8) & 0xFF;
	memory[socketBase(socket) + SN_DIPR0 + 3] = ntohl(addr.sin_addr.s_addr) & 0xFF;
	writeReg16(socket, SN_DPORT0, ntohs(addr.sin_port));
	updateSocketStatus(socket, SOCKET_STATUS_ESTABLISHED);
	updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_CON);
}

void W5100::pollTcpReceive(unsigned socket)
{
	auto& rt = runtime[socket];
	if (rt.fd == OPENMSX_INVALID_SOCKET || rt.peerClosed || !hasRxSpace(socket, 1)) return;

	std::array<byte, 512> buffer;
	while (hasRxSpace(socket, 1)) {
		auto free = RX_BUFFER_SIZE - rt.rxQueued;
		auto n = recv(rt.fd, reinterpret_cast<char*>(buffer.data()), std::min<size_t>(buffer.size(), free), 0);
		if (n < 0) {
			if (socketWouldBlock()) break;
			printDebug("[W5100] TCP RECV socket=", socket, " recv err=", errno, ", closing");
			closeRuntimeSocket(socket);
			updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
			updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_TIMEOUT);
			return;
		}
		if (n == 0) {
			// Peer sent FIN. Transition to CLOSE_WAIT on first EOF.
			// Stay there: do not auto-transition to CLOSED and do not
			// reset the RX pointers, because the RX buffer may still
			// hold data the guest has not drained yet. On a real W5100
			// the socket stays in CLOSE_WAIT until the guest issues an
			// explicit DISCON / CLOSE command; the application keeps
			// draining SN_RX_RSR in the meantime. We mark peerClosed
			// so pollTcpReceive stops trying to recv() from the now-FIN
			// socket, and we only close the host fd here — the W5100
			// buffer state is preserved.
			rt.peerClosed = true;
			closeHostSocket(socket);
			if (sockets[socket].status != SOCKET_STATUS_CLOSE_WAIT) {
				updateSocketStatus(socket, SOCKET_STATUS_CLOSE_WAIT);
			}
			updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_DISCON);
			return;
		}
		queueReceivedTcpData(socket, buffer.data(), size_t(n));
	}
}

void W5100::pollUdpReceive(unsigned socket)
{
	auto& rt = runtime[socket];
	if (rt.fd == OPENMSX_INVALID_SOCKET || !hasRxSpace(socket, 8)) return;

	std::array<byte, 2048> buffer;
	while (hasRxSpace(socket, 8)) {
		sockaddr_in addr{};
		SystemSockLen addrLen = sizeof(addr);
		auto n = recvfrom(rt.fd, reinterpret_cast<char*>(buffer.data()), int(buffer.size()), 0,
		                  reinterpret_cast<sockaddr*>(&addr), &addrLen);
		if (n < 0) {
			if (socketWouldBlock()) break;
			closeRuntimeSocket(socket);
			updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
			updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_TIMEOUT);
			return;
		}
		{
			auto ip = ntohl(addr.sin_addr.s_addr);
			auto port = ntohs(addr.sin_port);
			printDebug("[W5100] UDP RECV socket=", socket, " src=",
			           (ip>>24)&0xFF, '.', (ip>>16)&0xFF, '.', (ip>>8)&0xFF, '.', ip&0xFF,
			           ':', port, " len=", size_t(n));
			if (port == 53 && n >= 12) {
				printDebug("[W5100]   DNS response id=0x",
				           hex_string<2>(buffer[0]), hex_string<2>(buffer[1]),
				           " flags=0x",
				           hex_string<2>(buffer[2]), hex_string<2>(buffer[3]),
				           " ancount=",
				           unsigned((unsigned(buffer[6])<<8)|unsigned(buffer[7])));
				// Parse answer section to show resolved IP
				size_t pos = 12;
				// Skip question section
				auto qdcount = (unsigned(buffer[4])<<8)|unsigned(buffer[5]);
				for (unsigned q = 0; q < qdcount && pos < size_t(n); ++q) {
					while (pos < size_t(n) && buffer[pos] != 0) {
						if ((buffer[pos] & 0xC0) == 0xC0) { pos += 2; break; }
						pos += unsigned(buffer[pos]) + 1;
					}
					if (pos < size_t(n) && buffer[pos] == 0) pos++;
					pos += 4; // qtype + qclass
				}
				// Show first answer
				auto ancount = (unsigned(buffer[6])<<8)|unsigned(buffer[7]);
				for (unsigned a = 0; a < ancount && pos + 12 <= size_t(n); ++a) {
					// Skip name (may be compressed)
					if ((buffer[pos] & 0xC0) == 0xC0) pos += 2;
					else { while (pos < size_t(n) && buffer[pos] != 0) pos += unsigned(buffer[pos]) + 1; pos++; }
					auto rtype = (unsigned(buffer[pos])<<8)|unsigned(buffer[pos+1]);
					auto rdlen = (unsigned(buffer[pos+8])<<8)|unsigned(buffer[pos+9]);
					pos += 10;
					if (rtype == 1 && rdlen == 4 && pos + 4 <= size_t(n)) {
						printDebug("[W5100]   DNS answer: A record = ",
						           unsigned(buffer[pos]), '.', unsigned(buffer[pos+1]), '.',
						           unsigned(buffer[pos+2]), '.', unsigned(buffer[pos+3]));
					}
					pos += rdlen;
				}
			}
		}
		(void)queueReceivedUdpData(socket, addr, buffer.data(), size_t(n));
	}
}

void W5100::pollTcpSend(unsigned socket)
{
	auto& rt = runtime[socket];
	if (rt.fd == OPENMSX_INVALID_SOCKET || rt.pendingTx.empty()) {
		updateTxFreeSpace(socket);
		return;
	}

	auto sent = sock_send(rt.fd, reinterpret_cast<const char*>(rt.pendingTx.data()), rt.pendingTx.size());
	if (sent < 0) {
		if (socketWouldBlock()) {
			updateTxFreeSpace(socket);
			return;
		}
		closeHostSocket(socket);
		updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
		updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_TIMEOUT);
		return;
	}
	if (sent > 0) {
		rt.pendingTx.erase(rt.pendingTx.begin(), rt.pendingTx.begin() + sent);
		rt.txReadPointer = uint16_t(rt.txReadPointer + sent);
		if (rt.pendingTx.empty()) {
			rt.txSendPointer = rt.txReadPointer;
		}
	}
	updateTxFreeSpace(socket);
	if (rt.pendingTx.empty()) {
		updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_SEND_OK);
	}
}

W5100::DhcpHandling W5100::maybeHandleDhcp(unsigned socket, std::span<const byte> payload)
{
	if ((getLocalPort(socket) != 68) || (readReg16(socket, SN_DPORT0) != 67)) return DhcpHandling::NOT_DHCP;

	auto messageType = parseDhcpMessageType(payload);
	if (!messageType) return DhcpHandling::NOT_DHCP;

	byte replyType = 0;
	switch (*messageType) {
	case 1: replyType = 2; break; // DISCOVER -> OFFER
	case 3: replyType = 5; break; // REQUEST -> ACK
	case 8: replyType = 5; break; // INFORM -> ACK
	default: return DhcpHandling::NOT_DHCP;
	}

	auto config = queryHostNetworkConfig();
	if (!config) {
		updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_TIMEOUT);
		return DhcpHandling::BLOCKED;
	}

	auto reply = buildDhcpReply(*config, payload, *messageType, replyType);
	sockaddr_in server{};
	server.sin_family = AF_INET;
	server.sin_port = htons(67);
	server.sin_addr.s_addr = htonl(config->serverId);
	if (!queueReceivedUdpData(socket, server, reply.data(), reply.size())) {
		updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_TIMEOUT);
		return DhcpHandling::BLOCKED;
	}
	updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_SEND_OK);
	return DhcpHandling::HANDLED;
}

W5100::DnsHandling W5100::maybeHandleDns(unsigned socket, std::span<const byte> payload)
{
	if (readReg16(socket, SN_DPORT0) != 53) return DnsHandling::NOT_DNS;
	if (payload.size() < 12) return DnsHandling::NOT_DNS;

	// Parse DNS header
	auto qdcount = (unsigned(payload[4]) << 8) | unsigned(payload[5]);
	if (qdcount == 0) return DnsHandling::NOT_DNS;

	// Extract query name
	std::string hostname;
	size_t pos = 12;
	while (pos < payload.size() && payload[pos] != 0) {
		auto labelLen = unsigned(payload[pos++]);
		if ((labelLen & 0xC0) != 0) return DnsHandling::NOT_DNS; // compressed name, not expected in query
		if (pos + labelLen > payload.size()) return DnsHandling::NOT_DNS;
		if (!hostname.empty()) hostname += '.';
		for (unsigned j = 0; j < labelLen; ++j) {
			hostname += char(payload[pos++]);
		}
	}
	if (hostname.empty()) return DnsHandling::NOT_DNS;
	if (pos < payload.size()) pos++; // skip null terminator
	if (pos + 4 > payload.size()) return DnsHandling::NOT_DNS;
	auto qtype = (unsigned(payload[pos]) << 8) | unsigned(payload[pos + 1]);
	// auto qclass = (unsigned(payload[pos + 2]) << 8) | unsigned(payload[pos + 3]);
	pos += 4;

	// Only handle A record queries (type 1)
	if (qtype != 1) return DnsHandling::NOT_DNS;

	printDebug("[W5100] DNS intercept: resolving '", hostname, "'");

	// Resolve on host using getaddrinfo
	addrinfo hints{};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	addrinfo* result = nullptr;
	auto rc = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
	if (rc != 0 || !result) {
		printDebug("[W5100] DNS intercept: resolution failed for '", hostname, "': ", gai_strerror(rc));
		if (result) freeaddrinfo(result);
		return DnsHandling::FAILED;
	}

	// Collect resolved IPv4 addresses
	std::vector<uint32_t> addresses;
	for (auto* rp = result; rp; rp = rp->ai_next) {
		if (rp->ai_family == AF_INET) {
			auto* sa = reinterpret_cast<sockaddr_in*>(rp->ai_addr);
			addresses.push_back(ntohl(sa->sin_addr.s_addr));
		}
	}
	freeaddrinfo(result);

	if (addresses.empty()) {
		printDebug("[W5100] DNS intercept: no A records for '", hostname, "'");
		return DnsHandling::FAILED;
	}

	lastResolvedIp = addresses[0];
	for (auto ip : addresses) {
		printDebug("[W5100] DNS intercept: resolved '", hostname, "' -> ",
		           (ip >> 24) & 0xFF, '.', (ip >> 16) & 0xFF, '.',
		           (ip >> 8) & 0xFF, '.', ip & 0xFF);
	}

	// Build DNS response packet
	std::vector<byte> response;
	// Header: copy ID from query, set response flags
	response.push_back(payload[0]); // ID high
	response.push_back(payload[1]); // ID low
	response.push_back(0x81);       // QR=1, Opcode=0, AA=0, TC=0, RD=1
	response.push_back(0x80);       // RA=1, Z=0, RCODE=0 (no error)
	response.push_back(0x00);       // QDCOUNT high
	response.push_back(0x01);       // QDCOUNT low
	auto ancount = uint16_t(std::min<size_t>(addresses.size(), 255));
	response.push_back(byte(ancount >> 8)); // ANCOUNT high
	response.push_back(byte(ancount & 0xFF)); // ANCOUNT low
	response.push_back(0x00);       // NSCOUNT high
	response.push_back(0x00);       // NSCOUNT low
	response.push_back(0x00);       // ARCOUNT high
	response.push_back(0x00);       // ARCOUNT low

	// Question section: copy from query
	response.insert(response.end(), payload.begin() + 12, payload.begin() + pos);

	// Answer section
	for (size_t i = 0; i < ancount; ++i) {
		response.push_back(0xC0);   // name pointer
		response.push_back(0x0C);   // offset to question name
		response.push_back(0x00);   // TYPE A high
		response.push_back(0x01);   // TYPE A low
		response.push_back(0x00);   // CLASS IN high
		response.push_back(0x01);   // CLASS IN low
		response.push_back(0x00);   // TTL
		response.push_back(0x00);
		response.push_back(0x01);   // TTL = 300
		response.push_back(0x2C);
		response.push_back(0x00);   // RDLENGTH high
		response.push_back(0x04);   // RDLENGTH low
		auto ip = addresses[i];
		response.push_back(byte((ip >> 24) & 0xFF));
		response.push_back(byte((ip >> 16) & 0xFF));
		response.push_back(byte((ip >> 8) & 0xFF));
		response.push_back(byte(ip & 0xFF));
	}

	// Queue as UDP response from the DNS server
	auto dnsAddr = getDestinationAddress(socket);
	if (!queueReceivedUdpData(socket, dnsAddr, response.data(), response.size())) {
		return DnsHandling::FAILED;
	}
	updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_SEND_OK);
	return DnsHandling::HANDLED;
}

void W5100::queueReceivedTcpData(unsigned socket, const byte* data, size_t size)
{
	auto& rt = runtime[socket];
	auto length = uint16_t(std::min<size_t>(size, RX_BUFFER_SIZE - rt.rxQueued));
	writeRxBytes(socket, std::span{data, size_t(length)});
	rt.rxQueued += length;
	updateRxReceivedSize(socket);
	updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_RECV);
}

bool W5100::queueReceivedUdpData(unsigned socket, const sockaddr_in& addr, const byte* data, size_t size)
{
	auto payload = uint16_t(std::min<size_t>(size, 0xFFFF));
	auto total = uint16_t(8 + payload);
	if (!hasRxSpace(socket, total)) return false;

	auto ip = ntohl(addr.sin_addr.s_addr);
	std::array<byte, 8> header = {
		byte((ip >> 24) & 0xFF), byte((ip >> 16) & 0xFF),
		byte((ip >> 8) & 0xFF), byte(ip & 0xFF),
		byte((ntohs(addr.sin_port) >> 8) & 0xFF), byte(ntohs(addr.sin_port) & 0xFF),
		byte((payload >> 8) & 0xFF), byte(payload & 0xFF)
	};
	writeRxBytes(socket, header);
	writeRxBytes(socket, std::span{data, size});
	runtime[socket].rxQueued += total;
	runtime[socket].pendingUdp.push_back({total, payload, total});
	updateRxReceivedSize(socket);
	updateSocketInterrupt(socket, sockets[socket].interrupt | SN_IR_RECV);
	return true;
}

bool W5100::hasRxSpace(unsigned socket, uint16_t required) const
{
	return required <= (RX_BUFFER_SIZE - runtime[socket].rxQueued);
}

bool W5100::isGuestUdpPortInUse(unsigned socket, uint16_t port) const
{
	for (unsigned i = 0; i < SOCKET_COUNT; ++i) {
		if (i == socket) continue;
		if (runtime[i].fd == OPENMSX_INVALID_SOCKET) continue;
		if (sockets[i].status != SOCKET_STATUS_UDP) continue;
		if (getLocalPort(i) == port) return true;
	}
	return false;
}

void W5100::writeRxBytes(unsigned socket, std::span<const byte> data)
{
	auto& rt = runtime[socket];
	auto base = getRxBase(socket);
	for (auto b : data) {
		memory[base + rt.rxWriteOffset] = b;
		rt.rxWriteOffset = (rt.rxWriteOffset + 1) & (RX_BUFFER_SIZE - 1);
	}
}

std::vector<byte> W5100::extractTxBytes(unsigned socket, uint16_t length) const
{
	std::vector<byte> result;
	result.reserve(length);
	auto base = getTxBase(socket);
	auto start = runtime[socket].txSendPointer & (TX_BUFFER_SIZE - 1);
	for (uint16_t i = 0; i < length; ++i) {
		result.push_back(memory[base + ((start + i) & (TX_BUFFER_SIZE - 1))]);
	}
	return result;
}

sockaddr_in W5100::getDestinationAddress(unsigned socket) const
{
	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(readReg16(socket, SN_DPORT0));
	auto base = socketBase(socket) + SN_DIPR0;
	auto ip = (uint32_t(memory[base + 0]) << 24) |
	          (uint32_t(memory[base + 1]) << 16) |
	          (uint32_t(memory[base + 2]) << 8) |
	          uint32_t(memory[base + 3]);
	addr.sin_addr.s_addr = htonl(ip);
	return addr;
}

uint16_t W5100::getLocalPort(unsigned socket) const
{
	return readReg16(socket, SN_PORT0);
}

SOCKET W5100::createSocket(int type, int protocol) const
{
	auto fd = socket(AF_INET, type, protocol);
	if (fd == OPENMSX_INVALID_SOCKET) return fd;
	setNonBlocking(fd);
	int one = 1;
	if (type == SOCK_STREAM) {
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, std::bit_cast<char*>(&one), sizeof(one));
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, std::bit_cast<char*>(&one), sizeof(one));
	}
	return fd;
}

void W5100::setNonBlocking(SOCKET fd)
{
#ifdef _WIN32
	u_long mode = 1;
	ioctlsocket(fd, FIONBIO, &mode);
#else
	fcntl(fd, F_SETFL, O_NONBLOCK);
#endif
}

template<typename Archive>
void W5100::serialize(Archive& ar, unsigned /*version*/)
{
	ar.serialize("memory", memory,
	             "sockets", sockets);
	if constexpr (Archive::IS_LOADER) {
		for (unsigned socket = 0; socket < SOCKET_COUNT; ++socket) {
			closeHostSocket(socket);
			// Host socket state is intentionally not restored from savestates.
			// Reload into a coherent "socket closed" state instead of leaving
			// guest-visible socket state pretending to be connected/listening
			// without a backing host socket.
			resetSocketTransferState(socket);
			sockets[socket].command = 0;
			updateSocketStatus(socket, SOCKET_STATUS_CLOSED);
			updateSocketInterrupt(socket, 0);
			memory[socketBase(socket) + SN_CR] = 0;
		}
	}
}

template<typename Archive>
void serialize(Archive& ar, W5100::Socket& socket, unsigned /*version*/)
{
	ar.serialize("mode", socket.mode,
	             "command", socket.command,
	             "interrupt", socket.interrupt,
	             "status", socket.status,
	             "txWritePointer", socket.txWritePointer,
	             "rxReadPointer", socket.rxReadPointer);
}

INSTANTIATE_SERIALIZE_METHODS(W5100);

} // namespace openmsx
