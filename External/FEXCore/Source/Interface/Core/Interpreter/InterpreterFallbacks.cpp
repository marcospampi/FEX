#include "Interface/Core/Interpreter/InterpreterOps.h"
#include "Interface/Core/Interpreter/F80Ops.h"

#include <cstddef>
#include <cstdint>

namespace FEXCore::CPU {

template<typename R, typename... Args>
static FallbackInfo GetFallbackInfo(R(*fn)(Args...)) {
  return {FABI_UNKNOWN, (void*)fn};
}

template<>
FallbackInfo GetFallbackInfo(X80SoftFloat(*fn)(float)) {
  return {FABI_F80_F32, (void*)fn};
}

template<>
FallbackInfo GetFallbackInfo(X80SoftFloat(*fn)(double)) {
  return {FABI_F80_F64, (void*)fn};
}

template<>
FallbackInfo GetFallbackInfo(X80SoftFloat(*fn)(int16_t)) {
  return {FABI_F80_I16, (void*)fn};
}

template<>
FallbackInfo GetFallbackInfo(void(*fn)(uint16_t)) {
  return {FABI_VOID_U16, (void*)fn};
}

template<>
FallbackInfo GetFallbackInfo(X80SoftFloat(*fn)(int32_t)) {
  return {FABI_F80_I32, (void*)fn};
}

template<>
FallbackInfo GetFallbackInfo(float(*fn)(X80SoftFloat)) {
  return {FABI_F32_F80, (void*)fn};
}

template<>
FallbackInfo GetFallbackInfo(double(*fn)(X80SoftFloat)) {
  return {FABI_F64_F80, (void*)fn};
}

template<>
FallbackInfo GetFallbackInfo(int16_t(*fn)(X80SoftFloat)) {
  return {FABI_I16_F80, (void*)fn};
}

template<>
FallbackInfo GetFallbackInfo(int32_t(*fn)(X80SoftFloat)) {
  return {FABI_I32_F80, (void*)fn};
}

template<>
FallbackInfo GetFallbackInfo(int64_t(*fn)(X80SoftFloat)) {
  return {FABI_I64_F80, (void*)fn};
}

template<>
FallbackInfo GetFallbackInfo(uint64_t(*fn)(X80SoftFloat, X80SoftFloat)) {
  return {FABI_I64_F80_F80, (void*)fn};
}

template<>
FallbackInfo GetFallbackInfo(X80SoftFloat(*fn)(X80SoftFloat)) {
  return {FABI_F80_F80, (void*)fn};
}

template<>
FallbackInfo GetFallbackInfo(X80SoftFloat(*fn)(X80SoftFloat, X80SoftFloat)) {
  return {FABI_F80_F80_F80, (void*)fn};
}

bool InterpreterOps::GetFallbackHandler(IR::IROp_Header *IROp, FallbackInfo *Info) {
  uint8_t OpSize = IROp->Size;
  switch(IROp->Op) {
    case IR::OP_F80LOADFCW: {
      *Info = GetFallbackInfo(&FEXCore::CPU::OpHandlers<IR::OP_F80LOADFCW>::handle);
      return true;
    }

    case IR::OP_F80CVTTO: {
      auto Op = IROp->C<IR::IROp_F80CVTTo>();

      switch (Op->Size) {
        case 4: {
          *Info = GetFallbackInfo(&FEXCore::CPU::OpHandlers<IR::OP_F80CVTTO>::handle4);
          return true;
        }
        case 8: {
          *Info = GetFallbackInfo(&FEXCore::CPU::OpHandlers<IR::OP_F80CVTTO>::handle8);
          return true;
        }
      default: LogMan::Msg::DFmt("Unhandled size: {}", OpSize);
      }
      break;
    }
    case IR::OP_F80CVT: {
      switch (OpSize) {
        case 4: {
          *Info = GetFallbackInfo(&FEXCore::CPU::OpHandlers<IR::OP_F80CVT>::handle4);
          return true;
        }
        case 8: {
          *Info = GetFallbackInfo(&FEXCore::CPU::OpHandlers<IR::OP_F80CVT>::handle8);
          return true;
        }
        default: LogMan::Msg::DFmt("Unhandled size: {}", OpSize);
      }
      break;
    }
    case IR::OP_F80CVTINT: {
      auto Op = IROp->C<IR::IROp_F80CVTInt>();

      switch (OpSize) {
        case 2: {
          *Info = GetFallbackInfo(Op->Truncate ? &FEXCore::CPU::OpHandlers<IR::OP_F80CVTINT>::handle2t : &FEXCore::CPU::OpHandlers<IR::OP_F80CVTINT>::handle2);
          return true;
        }
        case 4: {
          *Info = GetFallbackInfo(Op->Truncate ? &FEXCore::CPU::OpHandlers<IR::OP_F80CVTINT>::handle4t : &FEXCore::CPU::OpHandlers<IR::OP_F80CVTINT>::handle4);
          return true;
        }
        case 8: {
          *Info = GetFallbackInfo(Op->Truncate ? &FEXCore::CPU::OpHandlers<IR::OP_F80CVTINT>::handle8t : &FEXCore::CPU::OpHandlers<IR::OP_F80CVTINT>::handle8);
          return true;
        }
        default: LogMan::Msg::DFmt("Unhandled size: {}", OpSize);
      }
      break;
    }
    case IR::OP_F80CMP: {
      auto Op = IROp->C<IR::IROp_F80Cmp>();

      static constexpr std::array handlers{
        &FEXCore::CPU::OpHandlers<IR::OP_F80CMP>::handle<0>,
        &FEXCore::CPU::OpHandlers<IR::OP_F80CMP>::handle<1>,
        &FEXCore::CPU::OpHandlers<IR::OP_F80CMP>::handle<2>,
        &FEXCore::CPU::OpHandlers<IR::OP_F80CMP>::handle<3>,
        &FEXCore::CPU::OpHandlers<IR::OP_F80CMP>::handle<4>,
        &FEXCore::CPU::OpHandlers<IR::OP_F80CMP>::handle<5>,
        &FEXCore::CPU::OpHandlers<IR::OP_F80CMP>::handle<6>,
        &FEXCore::CPU::OpHandlers<IR::OP_F80CMP>::handle<7>,
      };

      *Info = GetFallbackInfo(handlers[Op->Flags]);
      return true;
    }

    case IR::OP_F80CVTTOINT: {
      auto Op = IROp->C<IR::IROp_F80CVTToInt>();

      switch (Op->Size) {
        case 2: {
          *Info = GetFallbackInfo(&FEXCore::CPU::OpHandlers<IR::OP_F80CVTTOINT>::handle2);
          return true;
        }
        case 4: {
          *Info = GetFallbackInfo(&FEXCore::CPU::OpHandlers<IR::OP_F80CVTTOINT>::handle4);
          return true;
        }
        default: LogMan::Msg::DFmt("Unhandled size: {}", OpSize);
      }
      break;
    }

#define COMMON_X87_OP(OP) \
    case IR::OP_F80##OP: { \
      *Info = GetFallbackInfo(&FEXCore::CPU::OpHandlers<IR::OP_F80##OP>::handle); \
      return true; \
    }

    // Unary
    COMMON_X87_OP(ROUND)
    COMMON_X87_OP(F2XM1)
    COMMON_X87_OP(TAN)
    COMMON_X87_OP(SQRT)
    COMMON_X87_OP(SIN)
    COMMON_X87_OP(COS)
    COMMON_X87_OP(XTRACT_EXP)
    COMMON_X87_OP(XTRACT_SIG)
    COMMON_X87_OP(BCDSTORE)
    COMMON_X87_OP(BCDLOAD)

    // Binary
    COMMON_X87_OP(ADD)
    COMMON_X87_OP(SUB)
    COMMON_X87_OP(MUL)
    COMMON_X87_OP(DIV)
    COMMON_X87_OP(FYL2X)
    COMMON_X87_OP(ATAN)
    COMMON_X87_OP(FPREM1)
    COMMON_X87_OP(FPREM)
    COMMON_X87_OP(SCALE)

    default:
      break;
  }

  return false;
}


}
