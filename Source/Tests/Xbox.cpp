#include "Xbox/xbe_loader.hpp"

#include "Common/ArgumentLoader.h"
#include "CommonCore/HostFactory.h"

#include "Tests/LinuxSyscalls/LinuxAllocator.h"
#include "Tests/LinuxSyscalls/Syscalls.h"
#include "Tests/LinuxSyscalls/x32/Syscalls.h"
#include "Tests/LinuxSyscalls/x64/Syscalls.h"
#include "Tests/LinuxSyscalls/SignalDelegator.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/CPUBackend.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>

#include <memory>
#include <sys/types.h>
#include <signal.h>

namespace FEXCore::Core
{
    struct InternalThreadState;
}

void MsgHandler(LogMan::DebugLevels Level, char const *Message)
{
    const char *CharLevel{nullptr};

    switch (Level)
    {
    case LogMan::NONE:
        CharLevel = "NONE";
        break;
    case LogMan::ASSERT:
        CharLevel = "ASSERT";
        break;
    case LogMan::ERROR:
        CharLevel = "ERROR";
        break;
    case LogMan::DEBUG:
        CharLevel = "DEBUG";
        break;
    case LogMan::INFO:
        CharLevel = "Info";
        break;
    default:
        CharLevel = "???";
        break;
    }
    fmt::print("[{}] {}\n", CharLevel, Message);
}

void AssertHandler(char const *Message)
{
    fmt::print("[ASSERT] {}\n", Message);
}

int main(int argc, char *argv[])
{
    LogMan::Throw::InstallHandler(AssertHandler);
    LogMan::Msg::InstallHandler(MsgHandler);

    FEXCore::Config::Initialize();
    FEXCore::Config::Load();

    if (argc < 2)
    {
        LogMan::Msg::EFmt("Not enough arguments");
        return 1;
    }

    XBELoader loader(argv[1]);

    FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "0");
    FEXCore::Context::InitializeStaticTables(FEXCore::Context::MODE_32BIT);

    auto ctx = FEXCore::Context::CreateNewContext();

    FEXCore::Context::SetCustomCPUBackendFactory(ctx, HostFactory::CPUCreationFactory);

    FEXCore::Context::InitializeContext(ctx);
    
    FEXCore::Allocator::SetupHooks();
    auto allocator = FEX::HLE::CreatePassthroughAllocator();

    {
        auto map_mem = loader.MapMemory(
            [&allocator](void *addr, size_t length, int prot, int flags, int fd, off_t offset)
            {
                return allocator->mmap(addr, length, prot, flags, fd, offset);
            },
            [&allocator](void *addr, size_t length)
            {
                return allocator->munmap(addr, length);
            }
        );
        if (!map_mem)
        {
            LogMan::Msg::EFmt("Failed to map xbe file.");
            return -ENOEXEC;
        }
        else {
            LogMan::Msg::IFmt("Mapped!");
        }
    }

    auto signal_delegation = std::make_unique<FEX::HLE::SignalDelegator>();
    auto syscall_handler = FEX::HLE::x32::CreateHandler(ctx, signal_delegation.get(), std::move(allocator));

    bool didFault = false;

    signal_delegation->RegisterFrontendHostSignalHandler(
        SIGSEGV, [&didFault](FEXCore::Core::InternalThreadState *thread, int signal, void *info, void *ucontext)
        {
            didFault = true;
            return false;
        },
        true);
    FEXCore::Context::SetSignalDelegator(ctx, signal_delegation.get());
    FEXCore::Context::SetSyscallHandler(ctx, syscall_handler.get());
    if (!FEXCore::Context::InitCore(ctx, &loader))
    {
        LogMan::Msg::EFmt("Fuck");
        return 1;
    }
    FEXCore::Context::RunUntilExit(ctx);

    FEXCore::Core::CPUState state;
    FEXCore::Context::GetCPUState(ctx, &state);
    bool passed = !didFault;

    {
        LogMan::Msg::IFmt("Context:\n"
            "\tEIP:\t{:08X}\n"
            "\tEAX:\t{:08X}\n"
            "\tEBX:\t{:08X}\n"
            "\tECX:\t{:08X}\n"
            "\tEDX:\t{:08X}\n"
            "\tESI:\t{:08X}\n"
            "\tEDI:\t{:08X}\n"
            "\tEBP:\t{:08X}\n"
            "\tESP:\t{:08X}\n",
            state.rip,
            state.gregs[0],
            state.gregs[1],
            state.gregs[2],
            state.gregs[3],
            state.gregs[4],
            state.gregs[5],
            state.gregs[6],
            state.gregs[7]
        );
    }


    LogMan::Msg::IFmt("Faulted? {}", didFault ? "Yes" : "No");
    LogMan::Msg::IFmt("Passed? {}", passed ? "Yes" : "No");

    signal_delegation.reset();
    syscall_handler.reset();

    FEXCore::Context::DestroyContext(ctx);
    FEXCore::Context::ShutdownStaticTables();

    FEXCore::Config::Shutdown();

    LogMan::Throw::UnInstallHandlers();
    LogMan::Msg::UnInstallHandlers();

    FEXCore::Allocator::ClearHooks();

    return passed ? 0 : -1;
}