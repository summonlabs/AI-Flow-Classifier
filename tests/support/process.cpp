// AI Flow Classifier 1.0.0
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0

#include "process.hpp"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#if defined(AIFC_PLATFORM_WINDOWS)
#include <windows.h>
#else
#include <csignal>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "ai_flow_classifier/io/files.hpp"

namespace aifc_test {
namespace {

#if defined(AIFC_PLATFORM_WINDOWS)

[[nodiscard]] std::string quote_argument(const std::string& argument) {
  // The Windows command line rules: an argument containing a space or a quote must be
  // wrapped, and embedded quotes are escaped with a backslash.
  if (!argument.empty() && argument.find_first_of(" \t\"") == std::string::npos) {
    return argument;
  }
  std::string out = "\"";
  for (char ch : argument) {
    if (ch == '"') out.push_back('\\');
    out.push_back(ch);
  }
  out.push_back('"');
  return out;
}

#endif

}  // namespace

ChildProcess::~ChildProcess() {
  if (running()) {
    // A child that outlives its test is a leaked process: it holds the test binary open, it keeps
    // listening on a port, and it turns the next failure into a confusing link error.  Terminating it
    // here is the difference between a test that fails and a test suite that hangs.
    const aifc::Status killed = kill();
    if (!killed) {
      // The kill can legitimately fail if the child already exited; the handle is released either
      // way so that nothing is leaked.
      close();
    }
  }
  close();
}

ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : handle_(other.handle_), process_id_(other.process_id_), output_path_(std::move(other.output_path_)) {
  other.handle_ = nullptr;
  other.process_id_ = 0;
}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    process_id_ = other.process_id_;
    output_path_ = std::move(other.output_path_);
    other.handle_ = nullptr;
    other.process_id_ = 0;
  }
  return *this;
}

void ChildProcess::close() noexcept {
  if (handle_ == nullptr) return;
#if defined(AIFC_PLATFORM_WINDOWS)
  ::CloseHandle(static_cast<HANDLE>(handle_));
#else
  // On POSIX the child was already reaped by wait() or kill(); nothing is owned here.
#endif
  handle_ = nullptr;
}

aifc::Result<ChildProcess> ChildProcess::spawn(const std::string& executable,
                                              const std::string& child_mode_argument,
                                              const std::vector<std::string>& extra_arguments,
                                              const std::string& working_directory,
                                              const std::string& output_path) {
  ChildProcess child;
  child.output_path_ = output_path;

#if defined(AIFC_PLATFORM_WINDOWS)
  // The child is started directly, with the output file passed as an inherited handle.
  //
  // An earlier version wrapped the command in "cmd.exe /c ... > file 2>&1".  That works, and it also
  // means the file is held open by the console host rather than by the child: terminating the child
  // leaves the handle behind, so the scratch directory cannot be removed and the *next* test run
  // starts from a different filesystem state than this one did.  Owning the handle here means killing
  // the child releases it.
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;
  attributes.lpSecurityDescriptor = nullptr;
  HANDLE output = ::CreateFileA(output_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                &attributes, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (output == INVALID_HANDLE_VALUE) {
    return aifc::Status::failure(aifc::ErrorCode::IO_ERROR,
                                 "cannot open the child output file " + output_path + ": error " +
                                     std::to_string(::GetLastError()));
  }

  std::string command = quote_argument(executable) + " " + quote_argument(child_mode_argument);
  for (const std::string& argument : extra_arguments) {
    command += " " + quote_argument(argument);
  }
  std::vector<char> mutable_command(command.begin(), command.end());
  mutable_command.push_back('\0');

  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
  startup.hStdOutput = output;
  startup.hStdError = output;
  PROCESS_INFORMATION information{};
  const std::string directory = working_directory.empty() ? std::string() : working_directory;
  const BOOL created = ::CreateProcessA(
      nullptr, mutable_command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
      directory.empty() ? nullptr : directory.c_str(), &startup, &information);
  // The parent's copy of the handle is closed immediately: if the parent held it too, the file would
  // stay locked for as long as the parent lives, which is the same leak in a different place.
  ::CloseHandle(output);
  if (created == 0) {
    const DWORD error = ::GetLastError();
    return aifc::Status::failure(aifc::ErrorCode::IO_ERROR,
                                 "CreateProcess failed for " + executable + " with error " +
                                     std::to_string(error));
  }
  ::CloseHandle(information.hThread);
  child.handle_ = information.hProcess;
  child.process_id_ = static_cast<std::uint64_t>(information.dwProcessId);
  return child;
#else
  const pid_t pid = ::fork();
  if (pid < 0) {
    return aifc::Status::failure(aifc::ErrorCode::IO_ERROR, "fork failed");
  }
  if (pid == 0) {
    if (!working_directory.empty()) {
      if (::chdir(working_directory.c_str()) != 0) ::_exit(90);
    }
    std::FILE* file = std::fopen(output_path.c_str(), "wb");
    if (file != nullptr) {
      const int descriptor = ::fileno(file);
      if (descriptor >= 0) {
        ::dup2(descriptor, STDOUT_FILENO);
        ::dup2(descriptor, STDERR_FILENO);
      }
      // The FILE object is deliberately not closed: it now backs the child's standard
      // streams, and execv keeps the descriptors alive across the exec.
    }
    std::vector<std::string> arguments;
    arguments.push_back(executable);
    arguments.push_back(child_mode_argument);
    for (const std::string& argument : extra_arguments) arguments.push_back(argument);
    std::vector<char*> argv;
    argv.reserve(arguments.size() + 1);
    for (std::string& argument : arguments) argv.push_back(argument.data());
    argv.push_back(nullptr);
    ::execv(executable.c_str(), argv.data());
    ::_exit(91);
  }
  child.process_id_ = static_cast<std::uint64_t>(pid);
  child.handle_ = reinterpret_cast<void*>(static_cast<std::uintptr_t>(pid));
  return child;
#endif
}

aifc::Result<int> ChildProcess::wait() {
  if (handle_ == nullptr) {
    return aifc::Status::failure(aifc::ErrorCode::NOT_RUNNING, "the child has already been reaped");
  }
#if defined(AIFC_PLATFORM_WINDOWS)
  const DWORD result = ::WaitForSingleObject(static_cast<HANDLE>(handle_), INFINITE);
  if (result != WAIT_OBJECT_0) {
    return aifc::Status::failure(aifc::ErrorCode::IO_ERROR,
                                 "WaitForSingleObject returned " + std::to_string(result));
  }
  DWORD exit_code = 0;
  if (::GetExitCodeProcess(static_cast<HANDLE>(handle_), &exit_code) == 0) {
    return aifc::Status::failure(aifc::ErrorCode::IO_ERROR, "GetExitCodeProcess failed");
  }
  close();
  return static_cast<int>(exit_code);
#else
  int status = 0;
  const pid_t pid = static_cast<pid_t>(process_id_);
  for (;;) {
    const pid_t waited = ::waitpid(pid, &status, 0);
    if (waited == pid) break;
    if (waited < 0) {
      return aifc::Status::failure(aifc::ErrorCode::IO_ERROR, "waitpid failed");
    }
  }
  handle_ = nullptr;
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return -1;
#endif
}

aifc::Status ChildProcess::kill() {
  if (handle_ == nullptr) {
    return aifc::Status::failure(aifc::ErrorCode::NOT_RUNNING, "the child has already been reaped");
  }
#if defined(AIFC_PLATFORM_WINDOWS)
  // TerminateProcess is an immediate kill: no destructors, no flush, no chance to notify the
  // peer.  That is exactly the failure mode being tested.
  if (::TerminateProcess(static_cast<HANDLE>(handle_), 0xC0000005U) == 0) {
    return aifc::Status::failure(aifc::ErrorCode::IO_ERROR,
                                 "TerminateProcess failed with error " +
                                     std::to_string(::GetLastError()));
  }
  (void)::WaitForSingleObject(static_cast<HANDLE>(handle_), INFINITE);
  close();
  return aifc::Status::success();
#else
  const pid_t pid = static_cast<pid_t>(process_id_);
  if (::kill(pid, SIGKILL) != 0) {
    return aifc::Status::failure(aifc::ErrorCode::IO_ERROR, "kill(SIGKILL) failed");
  }
  int status = 0;
  (void)::waitpid(pid, &status, 0);
  handle_ = nullptr;
  return aifc::Status::success();
#endif
}

std::string ChildProcess::output() const {
  std::ifstream stream(output_path_, std::ios::binary);
  if (!stream) return std::string("<no child output was captured>");
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

}  // namespace aifc_test
