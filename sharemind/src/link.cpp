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
    std::string a_prefix;
    std::string b_prefix;
    std::uint64_t a_size;
    std::uint64_t b_size;
    float t;
    bool blocking;
    std::string bprefix;
    std::uint64_t u;

    try {
        namespace po = boost::program_options;

        po::options_description desc(
            "link\n"
            "Usage: link [OPTION]...\n\n"
            "Options");
        desc.add_options()
            ("conf,c", po::value<std::string>(), "Set the configuration file.")
            ("help", "Print this help")
            ("a_prefix", po::value<std::string>(), "Prefix of record key in dataset a")
            ("b_prefix", po::value<std::string>(), "Prefix of record key in dataset b")
            ("a_size", po::value<std::uint64_t>(&a_size), "Key is {a_prefix}{0}...{a_prefix}{a_size-1}")
            ("b_size", po::value<std::uint64_t>(&b_size), "Key is {b_prefix}{0}...{b_prefix}{b_size-1}")
            ("t", po::value<float>(&t), "Threshold")
            ("blocking", po::bool_switch(&blocking)->default_value(false), "Enable blocking")
            ("bprefix", po::value<std::string>()->default_value("b_"), "Prefix of blocking key")
            ("u", po::value<std::uint64_t>(&u)->default_value(0), "Obfuscation")
            ;

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return EXIT_SUCCESS;
        }

        if (!vm.count("t")) {
            std::cout << "Please enter the t.\n\n"
                << desc << std::endl;
            return EXIT_FAILURE;
        } else if(t < 0 or t > 1) {
            std::cout << "t must be in range [0, 1].\n\n"
                << desc << std::endl;
            return EXIT_FAILURE;
        }

        if (!vm.count("a_prefix") || !vm.count("b_prefix")) {
            std::cout << "Please enter the prefix.\n\n"
                << desc << std::endl;
            return EXIT_FAILURE;
        } else {
            a_prefix = vm["a_prefix"].as<std::string>();
            b_prefix = vm["b_prefix"].as<std::string>();
        }

        if (!vm.count("a_size") || !vm.count("b_size")) {
            std::cout << "Please enter the size.\n\n"
                << desc << std::endl;
            return EXIT_FAILURE;
        } else if(t <= 0) {
            std::cout << "size must be greater than 0.\n\n"
                << desc << std::endl;
            return EXIT_FAILURE;
        }

        if (vm.count("bprefix")) {
            bprefix = vm["bprefix"].as<std::string>();
        }

        if (vm.count("u")) {
            if (u < 0 || u > a_size * b_size) {
                std::cout << "Invalid u.\n\n"
                    << desc << std::endl;
                return EXIT_FAILURE;
            }
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
                    "link.log",
                    LogHard::FileAppender::OVERWRITE));
    const LogHard::Logger logger(logBackend);

    logger.info() << "Starting linking...";
    logger.info() << "Input parameters:";

    {
        logger.info() << "a_prefix: " << a_prefix;
        logger.info() << "a_size: " << a_size;
        logger.info() << "b_prefix: " << b_prefix;
        logger.info() << "b_size: " << b_size;
        logger.info() << "t: " << t;
        logger.info() << "blocking: " << blocking;
        logger.info() << "bprefix: " << bprefix;
        logger.info() << "u: " << u;
    }

    try {
        sm::SystemControllerGlobals systemControllerGlobals;
        sm::SystemController c(logger, *config);

        // Initialize the argument map and set the arguments
        sm::SystemController::ValueMap arguments;
        arguments["a_prefix"] =
                std::make_shared<sm::SystemController::Value>(
                    "",
                    "string",
                    newGlobalBuffer((const char *)a_prefix.c_str(), sizeof(char) * a_prefix.length()),
                    sizeof(char) * a_prefix.length());
        arguments["b_prefix"] =
                std::make_shared<sm::SystemController::Value>(
                    "",
                    "string",
                    newGlobalBuffer((const char *)b_prefix.c_str(), sizeof(char) * b_prefix.length()),
                    sizeof(char) * b_prefix.length());
        arguments["a_size"] =
                std::make_shared<sm::SystemController::Value>(
                    "",
                    "uint64",
                    newGlobalBuffer(&a_size, sizeof(std::uint64_t)),
                    sizeof(std::uint64_t));
        arguments["b_size"] =
                std::make_shared<sm::SystemController::Value>(
                    "",
                    "uint64",
                    newGlobalBuffer(&b_size, sizeof(std::uint64_t)),
                    sizeof(std::uint64_t));
        arguments["t"] =
                std::make_shared<sm::SystemController::Value>(
                    "pd_shared3p",
                    "float32",
                    newGlobalBuffer(&t, sizeof(float)),
                    sizeof(float));
        arguments["blocking"] =
                std::make_shared<sm::SystemController::Value>(
                    "",
                    "bool",
                    newGlobalBuffer(&blocking, sizeof(bool)),
                    sizeof(bool));
        arguments["bprefix"] =
                std::make_shared<sm::SystemController::Value>(
                    "",
                    "string",
                    newGlobalBuffer((const char *)bprefix.c_str(), sizeof(char) * bprefix.length()),
                    sizeof(char) * bprefix.length());
        arguments["u"] =
                std::make_shared<sm::SystemController::Value>(
                    "pd_shared3p",
                    "uint64",
                    newGlobalBuffer(&a_size, sizeof(std::uint64_t)),
                    sizeof(std::uint64_t));

        // Run code
        logger.info() << "Sending secret shared arguments and running SecreC bytecode on the servers";
        sm::SystemController::ValueMap results = c.runCode("link.sb", arguments);

        // Print the result
        sm::SystemController::ValueMap::const_iterator it = results.find("result");
        if (it == results.end()) {
            logger.error() << "Missing 'result' value.";
            return EXIT_FAILURE;
        }

        try {
            auto result = it->second->getVector<bool>();
            for (uint i = 0; i < (uint)a_size; i++) {
                for (uint j = 0; j < (uint)b_size; j++) {
                    uint idx = i * b_size + j;
                    if (result[idx]) {
                        logger.info() << "Found pair (" << i << "," << j << ")";
                    }
                }
            }
        } catch (const sm::SystemController::Value::ParseException & e) {
            logger.error() << "Failed to cast 'result' to appropriate type: " <<
                e.what();
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
        
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
