#ifndef BITCOIN_TEST_FUZZ_UTIL_SCRIPT_GRAMMAR_H
#define BITCOIN_TEST_FUZZ_UTIL_SCRIPT_GRAMMAR_H

#include <optional>
#include <script/script.h>
#include <test/fuzz/util.h>

#include <cstdint>
#include <vector>

typedef int64_t ConstNum;
class Expression;
class Statement;
class StatementSeq;

// [expression] [expression] <binop>
class BinaryOp
{
public:
    enum Op : uint8_t {
        ADD,
        SUB,
        BOOL_AND,
        BOOL_OR,
        EQUAL,
        EQUAL_VERIFY,
        NOT_EQUAL,
        LESS_THAN,
        GREATER_THAN,
        LESS_THAN_OR_EQUAL,
        GREATER_THAN_OR_EQUAL,
        MIN,
        MAX,
    };

    BinaryOp(Op op, Expression* left, Expression* right)
        : m_op{op}, m_left{left}, m_right{right} {}

    ~BinaryOp();

    const Op& GetOp() const { return m_op; }
    const Expression* GetLeftExpr() const { return m_left; }
    const Expression* GetRightExpr() const { return m_right; }

private:
    const Op m_op;
    const Expression* m_left;
    const Expression* m_right;
};

class StackOp
{
public:
    enum Op : uint8_t {
        TOALTSTACK,
        FROMALTSTACK,
        TWO_DROP,
        TWO_DUP,
        THREE_DUP,
        TWO_OVER,
        TWO_ROT,
        TWO_SWAP,
        IFDUP,
        DEPTH,
        DROP,
        DUP,
        NIP,
        OVER,
        PICK,
        ROLL,
        ROT,
        SWAP,
        TUCK,
    };

    StackOp(Op op) : m_op(op) {}

    const Op& GetOp() const { return m_op; };

private:
    const Op m_op;
};

class Expression
{
private:
    const bool m_nop;
    const ConstNum* m_constnum;
    const BinaryOp* m_binop;
    const StackOp* m_stackop;

public:
    Expression()
        : m_nop{true},
          m_constnum{nullptr},
          m_binop{nullptr},
          m_stackop{nullptr} {}
    Expression(ConstNum num)
        : m_nop{false},
          m_constnum{new ConstNum(num)},
          m_binop{nullptr},
          m_stackop{nullptr} {}
    Expression(BinaryOp::Op op, Expression* left, Expression* right)
        : m_nop{false},
          m_constnum{nullptr},
          m_binop{new BinaryOp(op, left, right)},
          m_stackop{nullptr} {}
    Expression(StackOp::Op op)
        : m_nop{false},
          m_constnum{nullptr},
          m_binop{nullptr},
          m_stackop{new StackOp(op)} {}

    ~Expression()
    {
        if (m_constnum) delete m_constnum;
        if (m_binop) delete m_binop;
        if (m_stackop) delete m_stackop;
    }

    bool IsNop() const { return m_nop; }
    const ConstNum* GetConstNum() const { return m_constnum; }
    const BinaryOp* GetBinaryOp() const { return m_binop; }
    const StackOp* GetStackOp() const { return m_stackop; }
};

// <expr> if <statements> else <statements>
class IfElseStatement
{
private:
    const Expression* m_cond;
    const StatementSeq* m_if_body;
    const StatementSeq* m_else_body;

public:
    IfElseStatement(Expression* cond, StatementSeq* if_seq, StatementSeq* else_seq)
        : m_cond{Assert(cond)},
          m_if_body{Assert(if_seq)},
          m_else_body{else_seq} {}
    IfElseStatement(IfElseStatement&) = delete;
    IfElseStatement(IfElseStatement&&) = delete;

    ~IfElseStatement();

    const Expression* GetCondExpr() const { return m_cond; }
    const StatementSeq* GetIfSequence() const { return m_if_body; }
    const StatementSeq* GetElseSequence() const { return m_else_body; }
};

/** Either a if/else statement or an expression. */
class Statement
{
private:
    const IfElseStatement* m_ifelse;
    const Expression* m_expr;

public:
    Statement(IfElseStatement* if_else_statement)
        : m_ifelse{if_else_statement}, m_expr{nullptr} {}
    Statement(Expression* expr)
        : m_ifelse{nullptr}, m_expr{expr} {}

    ~Statement();

    const IfElseStatement* GetIfElse() const { return m_ifelse; }
    const Expression* GetExpr() const { return m_expr; }
};

/** Sequences of statements */
class StatementSeq
{
private:
    std::vector<Statement*> m_statements;

public:
    ~StatementSeq();

    const std::vector<Statement*>& GetStatements() const { return m_statements; }
    std::vector<Statement*>& GetStatements() { return m_statements; }
};

class ScriptGrammar
{
private:
    FuzzedDataProvider& m_fuzzed_data_provider;

    StatementSeq* m_statement_seq;

public:
    ScriptGrammar(FuzzedDataProvider& data_provider);
    ~ScriptGrammar();

    CScript ToScript() const;
};

#endif
