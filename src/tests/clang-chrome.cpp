#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/Environment.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymExpr.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtVisitor.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Checkers/utility.h"
#include "clang/Lex/Lexer.h"  // for Lexer::getSourceText

using namespace clang;
using namespace ento;
using namespace taint;

// No custom program state maps are needed for this checker.

namespace {

class SAGenTestChecker : public Checker< check::PreCall > {
  mutable std::unique_ptr<BugType> BT;

public:
  SAGenTestChecker() 
    : BT(new BugType(this, "Unsafe Callback Binding", "API Misuse")) {}

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
  // Helper: Check if an expression contains both "base::Unretained" and "this"
  bool containsUnretainedThis(const Expr *E, CheckerContext &C) const;
};

bool SAGenTestChecker::containsUnretainedThis(const Expr *E, CheckerContext &C) const {
  if (!E)
    return false;
  
  // Check if the expression's source text contains "base::Unretained"
  if (!ExprHasName(E, "base::Unretained", C))
    return false;
  
  // Also check if the source text contains "this", to ensure it's unretained(this)
  if (!ExprHasName(E, "this", C))
    return false;
  
  return true;
}

void SAGenTestChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  // First, check if this call is to a function that binds a callback.
  // We expect asynchronous callback creation functions like base::BindOnce.
  const Expr *OriginExpr = Call.getOriginExpr();
  if (!OriginExpr)
    return;

  // Use utility to check if the call's source text contains "BindOnce".
  if (!ExprHasName(OriginExpr, "BindOnce", C))
    return;

  // Iterate over all arguments in the BindOnce call and inspect for unsafe use.
  for (unsigned i = 0, e = Call.getNumArgs(); i < e; ++i) {
    const Expr *ArgExpr = Call.getArgExpr(i);
    if (!ArgExpr)
      continue;

    // Look in the subtree of this argument, using the utility function.
    // We search for a child expression that corresponds to a call to base::Unretained.
    const CallExpr *ChildCall = findSpecificTypeInChildren<CallExpr>(ArgExpr);
    if (!ChildCall)
      continue;
    
    // Check if the child call contains "base::Unretained" and "this".
    if (containsUnretainedThis(ChildCall, C)) {
      ExplodedNode *N = C.generateNonFatalErrorNode();
      if (!N)
        return;
      
      auto Report = std::make_unique<PathSensitiveBugReport>(
          *BT, "Unsafe use of base::Unretained in asynchronous callback; use weak_ptr instead", N);
      Report->addRange(ChildCall->getSourceRange());
      C.emitReport(std::move(Report));
      // We report once per call.
      return;
    }
  }
}

} // end anonymous namespace

extern "C" void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<SAGenTestChecker>(
      "custom.SAGenTestChecker",
      "Detects unsafe use of base::Unretained in asynchronous callbacks; use weak_ptr instead",
      "");
}

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;
