#ifndef CASSETTEPLAYERCLI_HH
#define CASSETTEPLAYERCLI_HH

#include "CLIOption.hh"

namespace openmsx {

class CommandLineParser;

class CassettePlayerCLI final : public CLIOption, public CLIFileType
{
public:
	explicit CassettePlayerCLI(CommandLineParser& parser);
	void parseOption(const std::string& option,
	                 span<std::string>& cmdLine) override;
	std::string_view optionHelp() const override;
	void parseFileType(const std::string& filename,
	                   span<std::string>& cmdLine) override;
	std::string_view fileTypeHelp() const override;
	std::string_view fileTypeCategoryName() const override;

private:
	CommandLineParser& parser;
};

} // namespace openmsx

#endif
