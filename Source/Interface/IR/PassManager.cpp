#include "Interface/IR/Passes.h"
#include "Interface/IR/Passes/RegisterAllocationPass.h"
#include "Interface/IR/PassManager.h"

namespace FEXCore::IR {

void PassManager::AddDefaultPasses() {
  Passes.emplace_back(std::unique_ptr<FEXCore::IR::Pass>(CreateConstProp()));
  // XXX: Causes corrupted output in test app
  // Passes.emplace_back(std::unique_ptr<FEXCore::IR::Pass>(CreateRedundantContextLoadElimination()));
  Passes.emplace_back(std::unique_ptr<FEXCore::IR::Pass>(CreateRedundantFlagCalculationEliminination()));
  Passes.emplace_back(std::unique_ptr<FEXCore::IR::Pass>(CreateSyscallOptimization()));
  Passes.emplace_back(std::unique_ptr<FEXCore::IR::Pass>(CreatePassDeadContextStoreElimination()));

  // If the IR is compacted post-RA then the node indexing gets messed up and the backend isn't able to find the register assigned to a node
  // Compact before IR, don't worry about RA generating spills/fills
  Passes.emplace_back(std::unique_ptr<FEXCore::IR::Pass>(CreateIRCompaction()));
}

void PassManager::AddDefaultValidationPasses() {
  // Passes.emplace_back(std::unique_ptr<FEXCore::IR::Pass>(Validation::CreateIRValidation()));
}

bool PassManager::Run(OpDispatchBuilder *Disp) {
  bool Changed = false;
  for (auto const &Pass : Passes) {
    Changed |= Pass->Run(Disp);
  }
  return Changed;
}

}
