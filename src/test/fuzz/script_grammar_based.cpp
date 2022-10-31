#include <core_io.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/fuzz/util/script_grammar.h>

#include <iostream>

FUZZ_TARGET(script_grammar_based)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    const CScript script{ConsumeScript<ScriptGrammar>(fuzzed_data_provider)};
    const unsigned int flags = fuzzed_data_provider.ConsumeIntegral<unsigned int>();
    for (const auto sig_version : {SigVersion::BASE, SigVersion::WITNESS_V0}) {
        std::vector<std::vector<unsigned char>> stack;
        if (EvalScript(stack, script, flags, BaseSignatureChecker(), sig_version, nullptr))
            std::cout << FormatScript(script) << std::endl;
    }
}
