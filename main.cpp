#include <iostream>
#include <Utility/CppUtility.hpp>
#include <Utility/Socket.hpp>
#include <span>
#include <ranges>
#include "PeerToPeer.hpp"
#include "Router.hpp"

int main(int argc, char** argv)
{
	sw::Startup();

	uint16_t port = 80u;

	if (argc > 1) {
		size_t argPort;
		if (cpp::TryToInt64(argv[1], argPort)) {
			port = uint16_t(argPort);
		}
	}

#ifndef _DEBUG
	cpp::Logger::GlobalLoggerOptions.IncludeFileAndLine = false;
#endif
	cpp::Logger::GlobalLoggerOptions.IncludeDate = true;
	cpp::Logger::GlobalLoggerOptions.VerboseMode = false;

	LOG(INFO, "Peer to Peer Router; Starting at port {}", port);

	ClientMessageRouter cmr(port);
	std::thread router([&]() {
		cmr.Run();
	});

	router.join();

}
