#include <boost/program_options.hpp>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <LogHard/Backend.h>
#include <LogHard/FileAppender.h>
#include <LogHard/Logger.h>
#include <LogHard/StdAppender.h>
#include <memory>
#include <sharemind/controller/SystemController.h>
#include <sharemind/controller/SystemControllerConfiguration.h>
#include <sharemind/controller/SystemControllerGlobals.h>
#include <sharemind/DebugOnly.h>
#include <sharemind/GlobalDeleter.h>
// #include <sharemind/MakeUnique.h>
#include <sstream>
#include <string>

namespace sm = sharemind;

inline std::shared_ptr<void> newGlobalBuffer(std::size_t const size) {
    auto * const b = size ? ::operator new(size) : nullptr;
    try {
        return std::shared_ptr<void>(b, sm::GlobalDeleter());
    } catch (...) {
        ::operator delete(b);
        throw;
    }
}

inline std::shared_ptr<void> newGlobalBuffer(void const * const data,
                                             std::size_t const size)
{
    auto r(newGlobalBuffer(size));
    std::memcpy(r.get(), data, size);
    return r;
}

inline std::string int_to_hex(std::uint64_t i)
{
    std::stringstream stream;
    stream << "0x" << std::hex << i;
    return stream.str();
}

int main(int argc, char ** argv) {
    std::unique_ptr<sm::SystemControllerConfiguration> config;
    auto tokens = std::make_shared<std::vector<std::uint64_t>>();
    auto bkeys = std::make_shared<std::vector<std::string>>();
    std::vector<std::string> tokens_str;
    std::vector<std::string> bkeys_str;
    std::uint64_t id;
    std::string prefix;
    std::string bprefix;

    try {
        namespace po = boost::program_options;

        po::options_description desc(
            "upload\n"
            "Usage: upload [OPTION]...\n\n"
            "Options");
        desc.add_options()
            ("conf,c", po::value<std::string>(), "Set the configuration file.")
            ("help", "Print this help")
            ("id", po::value<std::uint64_t>(&id), "id of record")
            ("tokens,t", po::value<std::vector<std::string>>()->multitoken(), "tokens,t")
            ("prefix", po::value<std::string>(), "Dataset identifier")
            ("bkeys", po::value<std::vector<std::string>>()->multitoken(), "Blocking keys")
            ("bprefix", po::value<std::string>()->default_value("b_"), "Prefix of blocking key")
            ;

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return EXIT_SUCCESS;
        }

        if (!vm.count("tokens")) {
            std::cout << "Please enter the tokens.\n\n"
                << desc << std::endl;
            return EXIT_FAILURE;
        } else {
            tokens_str = vm["tokens"].as< std::vector<std::string> >();
            for (const auto s : tokens_str) {
                tokens->push_back(std::stol(s, nullptr, 0));
            }
        }
        if (!vm.count("id")) {
            std::cout << "Please enter the id.\n\n"
                << desc << std::endl;
            return EXIT_FAILURE;
        }

        if (vm.count("prefix")) {
            prefix = vm["prefix"].as<std::string>();
        }

        if (vm.count("bkeys")) {
            bkeys_str = vm["bkeys"].as< std::vector<std::string> >();
            for (const auto s : bkeys_str) {
                bkeys->push_back(s);
            }
        }

        if (vm.count("bprefix")) {
            bprefix = vm["bprefix"].as<std::string>();
        }

        if (vm.count("conf")) {
            config = std::make_unique<sm::SystemControllerConfiguration>(
                        vm["conf"].as<std::string>());
        } else {
            config = std::make_unique<sm::SystemControllerConfiguration>();
        }
    } catch(std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    auto logBackend(std::make_shared<LogHard::Backend>());
    logBackend->addAppender(std::make_shared<LogHard::StdAppender>());
    logBackend->addAppender(
                std::make_shared<LogHard::FileAppender>(
                    "upload.log",
                    LogHard::FileAppender::OVERWRITE));
    const LogHard::Logger logger(logBackend);

    logger.info() << "Starting uploading...";
    logger.info() << "Input parameters:";

    {
        logger.info() << "id: " << id;
    }

    {
        std::ostringstream oss;
        oss << "tokens: [ ";
        for (const auto val : *tokens) {
            oss << int_to_hex(val) << ' ';
        }
        oss << ']';
        logger.info() << oss.str();
    }
    
    {
        std::ostringstream oss;
        oss << "blocking keys: [ ";
        for (const auto val : *bkeys) {
            oss << val << ' ';
        }
        oss << ']';
        logger.info() << oss.str();
    }

    {
        logger.info() << "prefix: " << prefix;
        logger.info() << "bprefix: " << bprefix;
    }

    try {
        // upload
        {
            sm::SystemControllerGlobals systemControllerGlobals;
            sm::SystemController c(logger, *config);

            // Initialize the argument map and set the argument
            sm::SystemController::ValueMap arguments;
            arguments["id"] =
                    std::make_shared<sm::SystemController::Value>(
                        "",
                        "uint64",
                        newGlobalBuffer(&id, sizeof(std::uint64_t)),
                        sizeof(std::uint64_t));
            arguments["tokens"] =
                    std::make_shared<sm::SystemController::Value>(
                        "pd_shared3p",
                        "uint64",
                        std::shared_ptr<std::uint64_t>(tokens, tokens->data()),
                        sizeof(std::uint64_t) * tokens->size());
            arguments["prefix"] =
                    std::make_shared<sm::SystemController::Value>(
                        "",
                        "string",
                        newGlobalBuffer((const char *)prefix.c_str(), sizeof(char) * prefix.length()),
                        sizeof(char) * prefix.length());

            // Run code
            logger.info() << "Uploading tokens";
            sm::SystemController::ValueMap results = c.runCode("upload.sb", arguments);
        }

        // upload blocks
        for (const auto bkey : *bkeys) {
            sm::SystemControllerGlobals systemControllerGlobals;
            sm::SystemController c(logger, *config);

            // Initialize the argument map and set the argument
            sm::SystemController::ValueMap arguments;
            arguments["id"] =
                    std::make_shared<sm::SystemController::Value>(
                        "pd_shared3p",
                        "uint64",
                        newGlobalBuffer(&id, sizeof(std::uint64_t)),
                        sizeof(std::uint64_t));
            arguments["bkey"] =
                    std::make_shared<sm::SystemController::Value>(
                        "",
                        "string",
                        newGlobalBuffer((const char *)bkey.c_str(), sizeof(char) * bkey.length()),
                        sizeof(char) * bkey.length());
            arguments["prefix"] =
                    std::make_shared<sm::SystemController::Value>(
                        "",
                        "string",
                        newGlobalBuffer((const char *)prefix.c_str(), sizeof(char) * prefix.length()),
                        sizeof(char) * prefix.length());
            arguments["bprefix"] =
                    std::make_shared<sm::SystemController::Value>(
                        "",
                        "string",
                        newGlobalBuffer((const char *)bprefix.c_str(), sizeof(char) * bprefix.length()),
                        sizeof(char) * bprefix.length());

            // Run code
            logger.info() << "Uploading blocking key";
            sm::SystemController::ValueMap results = c.runCode("upload_blocks.sb", arguments);
        }

    } catch (const sm::SystemController::WorkerException & e) {
        logger.fatal() << "Multiple exceptions caught:";
        for (size_t i = 0u; i < e.numWorkers(); i++) {
            if (std::exception_ptr ep = e.nested_ptrs()[i]) {
                logger.fatal() << "  Exception from server " << i << ':';
                try {
                    std::rethrow_exception(std::move(ep));
                } catch (...) {
                    logger.printCurrentException<LogHard::Priority::Fatal>(
                            LogHard::Logger::StandardExceptionFormatter(4u));
                }
            }
        }
    } catch (const std::exception & e) {
        logger.error() << "Caught exception: " << e.what();
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
