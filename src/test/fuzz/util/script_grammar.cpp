#include "test/fuzz/util/script_grammar.h"
#include "script/script.h"
#include "test/fuzz/FuzzedDataProvider.h"
#include <cstdint>
#include <test/fuzz/util.h>

opcodetype StackOpToCScript(const StackOp::Op& op);
opcodetype BinOpToCScript(const BinaryOp::Op& op);
CScript BinaryOpToScript(const BinaryOp& binop);
CScript IfElseToScript(const IfElseStatement& if_else);
CScript ExpressionToScript(const Expression& expr);
CScript StatementToScript(const Statement& statement);
CScript StatementSeqToScript(const StatementSeq& seq);

IfElseStatement* GenerateIfElse(FuzzedDataProvider& data_provider);
Expression* GenerateExpression(FuzzedDataProvider& data_provider, bool allow_nop = true);
Statement* GenerateStatement(FuzzedDataProvider& data_provider);
StatementSeq* GenerateStatementSeq(FuzzedDataProvider& data_provider);

Statement::~Statement()
{
    if (m_ifelse) delete m_ifelse;
    if (m_expr) delete m_expr;
}

BinaryOp::~BinaryOp()
{
    delete Assert(m_left);
    delete Assert(m_right);
}

IfElseStatement::~IfElseStatement()
{
    delete Assert(m_cond);
    delete Assert(m_if_body);
    if (m_else_body) delete m_else_body;
}

StatementSeq::~StatementSeq()
{
    for (Statement* statement : m_statements) {
        delete statement;
    }
    m_statements.clear();
}

ScriptGrammar::ScriptGrammar(FuzzedDataProvider& data_provider)
    : m_fuzzed_data_provider{data_provider}
{
    m_statement_seq = GenerateStatementSeq(m_fuzzed_data_provider);
}

ScriptGrammar::~ScriptGrammar()
{
    delete Assert(m_statement_seq);
}

CScript ScriptGrammar::ToScript() const
{
    return StatementSeqToScript(*Assert(m_statement_seq));
}

Expression* GenerateExpression(FuzzedDataProvider& data_provider, bool allow_nop)
{
    enum ExprType : uint8_t {
        FROM_STACK,
        CONST_NUM,
        STACK_OP,
        BIN_OP,
    };

    ExprType type = static_cast<ExprType>(data_provider.ConsumeIntegralInRange<uint8_t>(allow_nop ? 0 : 1, BIN_OP));
    switch (type) {
    case FROM_STACK:
        return new Expression();
    case CONST_NUM:
        return new Expression(data_provider.ConsumeIntegral<int64_t>());
    case STACK_OP:
        return new Expression(static_cast<StackOp::Op>(
            data_provider.ConsumeIntegralInRange<uint8_t>(0, StackOp::TUCK)));
    case BIN_OP:
        return new Expression(
            static_cast<BinaryOp::Op>(data_provider.ConsumeIntegralInRange<uint8_t>(0, BinaryOp::MAX)),
            GenerateExpression(data_provider),
            GenerateExpression(data_provider));
    }
}

IfElseStatement* GenerateIfElse(FuzzedDataProvider& data_provider)
{
    bool has_else{data_provider.ConsumeBool()};
    auto* if_seq{GenerateStatementSeq(data_provider)};
    auto* else_seq{has_else ? GenerateStatementSeq(data_provider) : nullptr};
    if (if_seq) {
        return new IfElseStatement(GenerateExpression(data_provider), if_seq, else_seq);
    }

    return nullptr;
}

Statement* GenerateStatement(FuzzedDataProvider& data_provider)
{
    enum StatementType : uint8_t {
        IF_ELSE,
        EXPR,
    };

    StatementType type = static_cast<StatementType>(data_provider.ConsumeIntegralInRange<uint8_t>(0, EXPR));
    if (data_provider.remaining_bytes() <= 10) type = EXPR;

    switch (type) {
    case IF_ELSE:
        if (auto* if_else = GenerateIfElse(data_provider); if_else) {
            return new Statement(if_else);
        }

        return nullptr;
    case EXPR:
        return new Statement(GenerateExpression(data_provider));
    }
}

StatementSeq* GenerateStatementSeq(FuzzedDataProvider& data_provider)
{
    StatementSeq* seq = new StatementSeq();
    int num_statements{data_provider.ConsumeIntegralInRange<uint8_t>(0, 16)};
    for (int i = 0; i < num_statements; ++i) {
        if (auto* statement = GenerateStatement(data_provider); statement) {
            seq->GetStatements().push_back(statement);
        }
    }

    return seq;
}

opcodetype BinOpToCScript(const BinaryOp::Op& op)
{
    switch (op) {
    case BinaryOp::ADD:
        return OP_ADD;
    case BinaryOp::SUB:
        return OP_SUB;
    case BinaryOp::BOOL_AND:
        return OP_BOOLAND;
    case BinaryOp::BOOL_OR:
        return OP_BOOLOR;
    case BinaryOp::EQUAL:
        return OP_NUMEQUAL;
    case BinaryOp::EQUAL_VERIFY:
        return OP_NUMEQUALVERIFY;
    case BinaryOp::NOT_EQUAL:
        return OP_NUMNOTEQUAL;
    case BinaryOp::LESS_THAN:
        return OP_LESSTHAN;
    case BinaryOp::GREATER_THAN:
        return OP_GREATERTHAN;
    case BinaryOp::LESS_THAN_OR_EQUAL:
        return OP_LESSTHANOREQUAL;
    case BinaryOp::GREATER_THAN_OR_EQUAL:
        return OP_GREATERTHANOREQUAL;
    case BinaryOp::MIN:
        return OP_MIN;
    case BinaryOp::MAX:
        return OP_MAX;
    }
}

opcodetype StackOpToCScript(const StackOp::Op& op)
{
    switch (op) {
    case StackOp::TOALTSTACK:
        return OP_TOALTSTACK;
    case StackOp::FROMALTSTACK:
        return OP_FROMALTSTACK;
    case StackOp::TWO_DROP:
        return OP_2DROP;
    case StackOp::TWO_DUP:
        return OP_2DUP;
    case StackOp::THREE_DUP:
        return OP_3DUP;
    case StackOp::TWO_OVER:
        return OP_2OVER;
    case StackOp::TWO_ROT:
        return OP_2ROT;
    case StackOp::TWO_SWAP:
        return OP_2SWAP;
    case StackOp::IFDUP:
        return OP_IFDUP;
    case StackOp::DEPTH:
        return OP_DEPTH;
    case StackOp::DROP:
        return OP_DROP;
    case StackOp::DUP:
        return OP_DUP;
    case StackOp::NIP:
        return OP_NIP;
    case StackOp::OVER:
        return OP_OVER;
    case StackOp::PICK:
        return OP_PICK;
    case StackOp::ROLL:
        return OP_ROLL;
    case StackOp::ROT:
        return OP_ROT;
    case StackOp::SWAP:
        return OP_SWAP;
    case StackOp::TUCK:
        return OP_TUCK;
    }
}

CScript BinaryOpToScript(const BinaryOp& binop)
{
    CScript left{ExpressionToScript(*Assert(binop.GetLeftExpr()))};
    CScript right{ExpressionToScript(*Assert(binop.GetRightExpr()))};
    CScript out;
    out.insert(out.end(), left.begin(), left.end());
    out.insert(out.end(), right.begin(), right.end());
    out << BinOpToCScript(binop.GetOp());
    return out;
}

CScript ExpressionToScript(const Expression& expr)
{
    if (expr.IsNop()) return CScript();

    if (const auto* binop = expr.GetBinaryOp(); binop) {
        return BinaryOpToScript(*Assert(binop));
    }

    if (const auto* constnum = expr.GetConstNum(); constnum) {
        return CScript(*Assert(constnum));
    }

    if (const auto* stackop = expr.GetStackOp(); stackop) {
        return CScript(StackOpToCScript(stackop->GetOp()));
    }

    assert(false);
}

CScript IfElseToScript(const IfElseStatement& if_else)
{
    CScript cond{ExpressionToScript(*Assert(if_else.GetCondExpr()))};
    CScript if_body{StatementSeqToScript(*Assert(if_else.GetIfSequence()))};

    CScript out;
    out.insert(out.end(), cond.begin(), cond.end());
    out << OP_IF;
    out.insert(out.end(), if_body.begin(), if_body.end());

    if (const auto* else_seq = if_else.GetElseSequence(); else_seq) {
        // OP_ELSE is optional
        CScript else_body{StatementSeqToScript(*Assert(else_seq))};
        out << OP_ELSE;
        out.insert(out.end(), else_body.begin(), else_body.end());
    }

    out << OP_ENDIF;

    return out;
}

CScript StatementToScript(const Statement& statement)
{
    if (const auto* if_else = statement.GetIfElse(); if_else) {
        return IfElseToScript(*Assert(if_else));
    } else if (const auto* expr = statement.GetExpr(); expr) {
        return ExpressionToScript(*Assert(expr));
    }

    assert(false);
    return CScript();
}

CScript StatementSeqToScript(const StatementSeq& seq)
{
    CScript out;
    for (const Statement* statement : seq.GetStatements()) {
        CScript statement_script{StatementToScript(*Assert(statement))};
        out.insert(out.end(), statement_script.begin(), statement_script.end());
    }
    return out;
}
