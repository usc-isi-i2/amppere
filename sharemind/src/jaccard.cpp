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
    auto a = std::make_shared<std::vector<std::uint64_t>>();
    std::vector<std::string> a_str;
    auto b = std::make_shared<std::vector<std::uint64_t>>();
    std::vector<std::string> b_str;
    float t;
    // std::string method;

    try {
        namespace po = boost::program_options;

        po::options_description desc(
            "jaccard\n"
            "Usage: jaccard [OPTION]...\n\n"
            "Options");
        desc.add_options()
            ("conf,c", po::value<std::string>(), "Set the configuration file.")
            ("help", "Print this help")
            ("a", po::value<std::vector<std::string>>()->multitoken(), "record1")
            ("b", po::value<std::vector<std::string>>()->multitoken(), "record2")
            ("t", po::value<float>(&t), "threshold")
            // ("method", po::value<std::string>()->default_value("naive"), "method (naive|repeat|sort)")
            ;

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return EXIT_SUCCESS;
        }

        if (!vm.count("a")) {
            std::cout << "Please enter the a.\n\n"
                << desc << std::endl;
            return EXIT_FAILURE;
        } else {
            a_str = vm["a"].as< std::vector<std::string> >();
            for (const auto s : a_str) {
                a->push_back(std::stol(s, nullptr, 0));
            }
        }
        if (!vm.count("b")) {
            std::cout << "Please enter the b.\n\n"
                << desc << std::endl;
            return EXIT_FAILURE;
        } else {
            b_str = vm["b"].as< std::vector<std::string> >();
            for (const auto s : b_str) {
                b->push_back(std::stol(s, nullptr, 0));
            }
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
        // if (vm.count("method")) {
        //     method = vm["method"].as<std::string>();
        // }

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
                    "jaccard.log",
                    LogHard::FileAppender::OVERWRITE));
    const LogHard::Logger logger(logBackend);

    logger.info() << "Starting Jaccard computing...";
    logger.info() << "Input parameters:";

    {
        std::ostringstream oss;
        oss << "a: [ ";
        for (const auto val : *a) {
            oss << int_to_hex(val) << ' ';
        }
        oss << ']';
        logger.info() << oss.str();
    }

    {
        std::ostringstream oss;
        oss << "b: [ ";
        for (const auto val : *b) {
            oss << int_to_hex(val) << ' ';
        }
        oss << ']';
        logger.info() << oss.str();
    }

    {
        logger.info() << "t: " << t;
    }

    try {
        sm::SystemControllerGlobals systemControllerGlobals;
        sm::SystemController c(logger, *config);

        // Initialize the argument map and set the arguments
        sm::SystemController::ValueMap arguments;
        arguments["a"] =
                std::make_shared<sm::SystemController::Value>(
                    "pd_shared3p",
                    "uint64",
                    std::shared_ptr<std::uint64_t>(a, a->data()),
                    sizeof(std::uint64_t) * a->size());
        arguments["b"] =
                std::make_shared<sm::SystemController::Value>(
                    "pd_shared3p",
                    "uint64",
                    std::shared_ptr<std::uint64_t>(b, b->data()),
                    sizeof(std::uint64_t) * b->size());
        arguments["t"] =
                std::make_shared<sm::SystemController::Value>(
                    "pd_shared3p",
                    "float32",
                    newGlobalBuffer(&t, sizeof(float)),
                    sizeof(float));

        // Run code
        logger.info() << "Sending secret shared arguments and running SecreC bytecode on the servers";
        sm::SystemController::ValueMap results = c.runCode("jaccard.sb", arguments);

        // Print the result
        sm::SystemController::ValueMap::const_iterator it = results.find("result");
        if (it == results.end()) {
                logger.error() << "Missing 'result' value.";
                return EXIT_FAILURE;
        }

        try {
            auto result = it->second->getValue<bool>();
            logger.info() << "The result is: " << result;
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
