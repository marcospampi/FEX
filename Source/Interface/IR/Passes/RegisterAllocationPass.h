#include "Interface/IR/PassManager.h"
#include <vector>

namespace FEXCore::IR {
template<bool>
class IRListView;

class RegisterAllocationPass final : public FEXCore::IR::Pass {
public:
  struct RegisterSet;
  struct RegisterGraph;
  struct RegisterNode;

  static constexpr uint32_t GPRClass = 0;
  static constexpr uint32_t FPRClass = 1;

  RegisterAllocationPass();

  bool Run(OpDispatchBuilder *Disp) override;

  RegisterSet *AllocateRegisterSet(uint32_t RegisterCount, uint32_t ClassCount);
  void FreeRegisterSet(RegisterSet *Set);
  void AddRegisters(RegisterSet *Set, uint32_t Class, uint32_t RegistersBase, uint32_t RegisterCount);

  /**
   * @name Inference graph handling
   * @{ */

  RegisterGraph *AllocateRegisterGraph(RegisterSet *Set, uint32_t NodeCount);
  void FreeRegisterGraph();
  void ResetRegisterGraph(uint32_t NodeCount);
  void SetNodeClass(uint32_t Node, uint32_t Class);
  uint32_t GetNodeRegister(uint32_t Node);

  void AllocateRegisters();

  /**  @} */

  bool HasFullRA() const { return HadFullRA; }
  bool HadSpills() const { return HasSpills; }
  uint32_t SpillSlots() const { return SpillSlotCount; }

  void SetSupportsSpills(bool Supports) { Config_SupportsSpills = Supports; }

private:
  RegisterGraph *Graph;
  void FindNodeClasses(IRListView<false> *CurrentIR);

  struct LiveRange {
    uint32_t Begin;
    uint32_t End;
    uint32_t RematCost;
  };

  std::vector<LiveRange> LiveRanges;

  void CalculateLiveRange(IRListView<false> *CurrentIR);
  void CalculateNodeInterference(uint32_t NodeCount);

  void ClearSpillList(OpDispatchBuilder *Disp);

  RegisterNode *GetRegisterNode(uint32_t Node);
  IR::NodeWrapperIterator FindFirstUse(OpDispatchBuilder *Disp, OrderedNode* Node, IR::NodeWrapperIterator Begin, IR::NodeWrapperIterator End);

  bool HasSpills {};
  uint32_t SpillSlotCount {};
  bool HadFullRA {};

  bool Config_SupportsSpills {true};
};

}

