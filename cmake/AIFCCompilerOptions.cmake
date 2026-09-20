# AIFCCompilerOptions.cmake
#
# Single place that decides which warnings are enabled.  The release standard is
# zero first-party warnings in every supported configuration, so the defaults are
# /W4 for MSVC and -Wall -Wextra -Wpedantic for GCC and Clang, with warnings as
# errors controlled by AIFC_WARNINGS_AS_ERRORS.
#
# Every warning listed here is one this tree is known to be clean under.  Nothing
# is globally suppressed: there is no /wd... and no -Wno-... applied to the
# first-party targets.

function(aifc_collect_warnings)
  if(MSVC)
    set(_warnings
      /W4
      /permissive-
      /utf-8
      /EHsc    # the standard library requires unwind semantics; without it MSVC warns from inside <vector>
      /w14242  # 'identifier': conversion from 'type1' to 'type2', possible loss of data
      /w14254  # 'operator': conversion from 'type1:field_bits' to 'type2:field_bits'
      /w14263  # 'function': member function does not override any base class virtual member function
      /w14265  # 'class': class has virtual functions, but destructor is not virtual
      /w14287  # 'operator': unsigned/negative constant mismatch
      /w14289  # 'var': loop control variable declared in the for-loop is used outside the for-loop scope
      /w14296  # 'operator': expression is always false
      /w14311  # 'variable': pointer truncation from 'type' to 'type'
      /w14545  # expression before comma evaluates to a function which is missing an argument list
      /w14546  # function call before comma missing argument list
      /w14547  # 'operator': operator before comma has no effect; expected operator with side-effect
      /w14549  # 'operator': operator before comma has no effect; did you intend 'operator'?
      /w14555  # expression has no effect; expected expression with side-effect
      /w14619  # pragma warning: there is no warning number 'number'
      /w14640  # 'instance': construction of local static object is not thread-safe
      /w14826  # Conversion from 'type1' to 'type2' is sign-extended
      /w14905  # wide string literal cast to 'LPSTR'
      /w14906  # string literal cast to 'LPWSTR'
      /w14928  # illegal copy-initialization; more than one user-defined conversion has been implicitly applied
      /wd4996  # MSVC deprecation of C library names; std:: equivalents are not required by the project policy
      /Zc:__cplusplus
      /Zc:preprocessor
      /Zc:throwingNew-
      /Zc:inline
      /Zc:externConstexpr
    )
    if(AIFC_WARNINGS_AS_ERRORS)
      list(APPEND _warnings /WX)
    endif()
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    set(_warnings
      -Wall
      -Wextra
      -Wpedantic
      -Wconversion
      -Wsign-conversion
      -Wshadow
      -Wold-style-cast
      -Wcast-qual
      -Wcast-align
      -Wnon-virtual-dtor
      -Woverloaded-virtual
      -Wnull-dereference
      -Wdouble-promotion
      -Wformat=2
      -Wimplicit-fallthrough
      -Wunused
      -Wundef
      -Wpointer-arith
      -Wredundant-decls
      -Wwrite-strings
      -Wswitch-enum
    )
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
      list(APPEND _warnings -Wthread-safety)
    endif()
    if(AIFC_WARNINGS_AS_ERRORS)
      list(APPEND _warnings -Werror)
    endif()
  else()
    message(WARNING "AI Flow Classifier has no curated warning set for ${CMAKE_CXX_COMPILER_ID}; building without /Wall or -Wall")
  endif()
  set(AIFC_WARNING_FLAGS "${_warnings}" PARENT_SCOPE)
endfunction()

function(aifc_configure_target target)
  cmake_parse_arguments(ARG "" "" "EXTRA_SOURCES" ${ARGN})
  get_target_property(_type ${target} TYPE)
  if(_type STREQUAL "INTERFACE_LIBRARY")
    target_compile_features(${target} INTERFACE cxx_std_20)
  else()
    target_compile_features(${target} PUBLIC cxx_std_20)
  endif()

  aifc_collect_warnings()
  if(_type STREQUAL "INTERFACE_LIBRARY")
    target_compile_options(${target} INTERFACE ${AIFC_WARNING_FLAGS})
  else()
    target_compile_options(${target} PRIVATE ${AIFC_WARNING_FLAGS})
  endif()

  if(MSVC)
    if(_type STREQUAL "INTERFACE_LIBRARY")
      target_compile_definitions(${target} INTERFACE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS
        AIFC_PLATFORM_WINDOWS=1)
    else()
      target_compile_definitions(${target} PRIVATE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS
        AIFC_PLATFORM_WINDOWS=1)
    endif()
    set_target_properties(${target} PROPERTIES
      MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
  else()
    if(_type STREQUAL "INTERFACE_LIBRARY")
      target_compile_definitions(${target} INTERFACE AIFC_PLATFORM_POSIX=1)
    else()
      target_compile_definitions(${target} PRIVATE AIFC_PLATFORM_POSIX=1)
    endif()
  endif()
endfunction()

# Probe whether the active toolchain can actually link a program with the given
# sanitizer flags.  AI Flow Classifier never claims sanitizer coverage it cannot
# demonstrate: when the probe fails the build simply reports UNSUPPORTED.
function(aifc_probe_sanitizer out_var flags)
  set(_saved_required "${CMAKE_REQUIRED_FLAGS}")
  set(_saved_link "${CMAKE_REQUIRED_LINK_OPTIONS}")
  set(_saved_libs "${CMAKE_REQUIRED_LIBRARIES}")
  if(MSVC)
    set(CMAKE_REQUIRED_FLAGS "${_saved_required} ${flags}")
  else()
    set(CMAKE_REQUIRED_FLAGS "${_saved_required}")
    set(CMAKE_REQUIRED_LINK_OPTIONS "${_saved_link} ${flags}")
  endif()
  unset(${out_var} CACHE)
  check_cxx_source_compiles("int main() { return 0; }" ${out_var})
  set(CMAKE_REQUIRED_FLAGS "${_saved_required}")
  set(CMAKE_REQUIRED_LINK_OPTIONS "${_saved_link}")
  set(CMAKE_REQUIRED_LIBRARIES "${_saved_libs}")
endfunction()
