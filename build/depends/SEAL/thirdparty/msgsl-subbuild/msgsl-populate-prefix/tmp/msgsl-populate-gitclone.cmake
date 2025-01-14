
if(NOT "/home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/msgsl-subbuild/msgsl-populate-prefix/src/msgsl-populate-stamp/msgsl-populate-gitinfo.txt" IS_NEWER_THAN "/home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/msgsl-subbuild/msgsl-populate-prefix/src/msgsl-populate-stamp/msgsl-populate-gitclone-lastrun.txt")
  message(STATUS "Avoiding repeated git clone, stamp file is up to date: '/home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/msgsl-subbuild/msgsl-populate-prefix/src/msgsl-populate-stamp/msgsl-populate-gitclone-lastrun.txt'")
  return()
endif()

execute_process(
  COMMAND ${CMAKE_COMMAND} -E rm -rf "/home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/msgsl-src"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to remove directory: '/home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/msgsl-src'")
endif()

# try the clone 3 times in case there is an odd git clone issue
set(error_code 1)
set(number_of_tries 0)
while(error_code AND number_of_tries LESS 3)
  execute_process(
    COMMAND "/usr/bin/git"  clone --no-checkout --config "advice.detachedHead=false" "https://github.com/microsoft/GSL.git" "msgsl-src"
    WORKING_DIRECTORY "/home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty"
    RESULT_VARIABLE error_code
    )
  math(EXPR number_of_tries "${number_of_tries} + 1")
endwhile()
if(number_of_tries GREATER 1)
  message(STATUS "Had to git clone more than once:
          ${number_of_tries} times.")
endif()
if(error_code)
  message(FATAL_ERROR "Failed to clone repository: 'https://github.com/microsoft/GSL.git'")
endif()

execute_process(
  COMMAND "/usr/bin/git"  checkout a3534567187d2edc428efd3f13466ff75fe5805c --
  WORKING_DIRECTORY "/home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/msgsl-src"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to checkout tag: 'a3534567187d2edc428efd3f13466ff75fe5805c'")
endif()

set(init_submodules TRUE)
if(init_submodules)
  execute_process(
    COMMAND "/usr/bin/git"  submodule update --recursive --init 
    WORKING_DIRECTORY "/home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/msgsl-src"
    RESULT_VARIABLE error_code
    )
endif()
if(error_code)
  message(FATAL_ERROR "Failed to update submodules in: '/home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/msgsl-src'")
endif()

# Complete success, update the script-last-run stamp file:
#
execute_process(
  COMMAND ${CMAKE_COMMAND} -E copy
    "/home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/msgsl-subbuild/msgsl-populate-prefix/src/msgsl-populate-stamp/msgsl-populate-gitinfo.txt"
    "/home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/msgsl-subbuild/msgsl-populate-prefix/src/msgsl-populate-stamp/msgsl-populate-gitclone-lastrun.txt"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to copy script-last-run stamp file: '/home/yancheng/code/ringSNARK/build/depends/SEAL/thirdparty/msgsl-subbuild/msgsl-populate-prefix/src/msgsl-populate-stamp/msgsl-populate-gitclone-lastrun.txt'")
endif()

